from http_verifier import HttpVerifier
from crypto import (
    b64,
    generate_rsa_key,
    load_private_key,
    export_private_key,
    generate_jwk,
    sign_request,
    create_csr,
    export_csr_for_acme,
)

import aiohttp
import aio_pika
import base64
import json
import asyncio
import os.path
import os
from datetime import datetime, timezone, timedelta
import msgpack

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from samp20.asyncservice.amqp import decode

import logging

log = logging.getLogger(__name__)


class AcmeException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


# https://acme-v02.api.letsencrypt.org/directory


class AcmeService:
    def __init__(
        self,
        amqp,
        cert_folder,
        keyfile,
        verifiers,
        days_before_renewal=10,
        restart_command=None,
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        listen_queue="acme"
    ):
        self.amqp = amqp
        self.directory = directory_url
        self.listen_queue = listen_queue
        self.cert_folder = cert_folder
        self.keyfile = keyfile
        self.days_before_renewal = days_before_renewal
        self.restart_cmd = restart_command
        self.nonce = None

        self.verifiers = []
        for verifier in verifiers:
            if verifier["type"] == "http-01":
                self.verifiers.append(HttpVerifier(**verifier))

        self.pending_certs = set()

    async def start(self):
        self.http_session = aiohttp.ClientSession(
            headers={"Content-Type": "application/jose+json"}
        )
        self.directory = await self.requst_unsigned(self.directory)
        self.account = await Account.load(self.keyfile, self)
        for verifier in self.verifiers:
            await verifier.start()

        self.channel = await self.amqp.channel()
        queue = await self.channel.declare_queue(
            name=self.listen_queue,
            durable=True,
        )
        self.exchange = await self.channel.declare_exchange(
            name="amq.topic",
            type=aio_pika.ExchangeType.TOPIC,
            durable=True,
        )
        await queue.bind(self.exchange, routing_key="cert.renew.request")
        #TODO bind and allow certificate invalidation
        await queue.consume(self.on_message)

    async def stop(self):
        await self.http_session.close()
        for verifier in self.verifiers:
            await verifier.stop()

    async def on_message(self, message: aio_pika.IncomingMessage):
        with message.process():
            data = decode(message)
            if "certs" in data:
                for name, domains in data["certs"].items():
                    await self.create_new_cert(name, domains, 10)

    async def create_new_cert(self, cert_name, domains, check_remaining_days=None):
        if cert_name in self.pending_certs:
            return

        if check_remaining_days is not None:
            cert = self.load_cert(cert_name)
            if cert is not None:
                expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                remaining = expires - now
                if remaining.days > check_remaining_days:
                    return

        self.pending_certs.add(cert_name)
        try:
            order = await Order.create_new(self.account, domains)

            if order.status == "pending":
                authz_tasks = []
                for authz in order.authorizations:
                    if authz.status != "pending":
                        continue
                    verifier, challenge = self.find_verifier(authz)
                    coro = verifier.process_challenge(
                        challenge, self.account.thumbprint()
                    )
                    authz_tasks.append(asyncio.create_task(coro))
                if authz_tasks:
                    _ = asyncio.wait(authz_tasks, timeout=10.0)
                for _ in range(5):  # Wait until order is no longer pending
                    await order.update()
                    if order.status != "pending":
                        break
                    await asyncio.sleep(2.0)

            keyfile = os.path.join(self.cert_folder, cert_name + ".key")
            certfile = os.path.join(self.cert_folder, cert_name + ".cert")
            temp_keyfile = os.path.join(self.cert_folder, cert_name + ".tempkey")
            temp_certfile = os.path.join(self.cert_folder, cert_name + ".tempcert")

            if order.status == "ready":
                cert_key = generate_rsa_key()
                with open(temp_keyfile, "wb") as f:
                    f.write(export_private_key(cert_key))
                csr = create_csr(cert_key, domains)
                await order.finalize(csr)
                for _ in range(5):  # Wait until order is no longer ready
                    if order.status != "ready":
                        break
                    await asyncio.sleep(2.0)
                    await order.update()

            if order.status == "valid":
                cert = await order.download_cert()
                with open(temp_certfile, "wb") as f:
                    f.write(cert)
                if os.path.isfile(temp_keyfile) and os.path.isfile(temp_certfile):
                    try:
                        os.remove(keyfile)
                    except OSError:
                        pass
                    try:
                        os.remove(certfile)
                    except OSError:
                        pass
                    os.rename(temp_keyfile, keyfile)
                    os.rename(temp_certfile, certfile)
                    # Run a command to restart Nginx or whatever proxy is being used
                    data = msgpack.packb({
                        'certs': {cert_name: domains}
                    }, use_bin_type=True)
                    await self.exchange.publish(
                        aio_pika.Message(
                            body=data,
                            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                            content_encoding="application/msgpack"
                        ),
                        routing_key="cert.renew.complete"
                    )
            else:
                pass  # something went wrong with the order

        finally:
            self.pending_certs.remove(cert)

    def load_cert(self, domain):
        cert_file = os.path.join(self.cert_folder, domain + ".cert")
        try:
            with open(cert_file, "rb") as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        except OSError:
            return None

    def find_verifier(self, authz):
        for verifier in self.verifiers:
            for challenge in authz.challenges:
                if verifier.can_process(challenge):
                    return verifier, challenge
        return None, None

    async def get_nonce(self):
        if self.nonce is not None:
            nonce = self.nonce
            self.nonce = None
            return nonce
        else:
            resp = await self.http_session.head(self.directory["newNonce"])
            return resp.headers["Replay-Nonce"]

    async def post(self, endpoint, body):
        resp = await self.http_session.post(endpoint, data=body)
        self.nonce = resp.headers.get("Replay-Nonce", None)
        await check_resp(resp)
        return resp

    async def requst_unsigned(self, endpoint):
        resp = await self.http_session.get(endpoint)
        await check_resp(resp)
        return await resp.json()


class Order:
    def __init__(self, account, order_url):
        self.account = account
        self.order_url = order_url

        self.status = None
        self.authorizations = []
        self.identifiers = []
        self.error = None
        self.finalize_url = None
        self.cert_url = None
        self.raw_data = None

    @classmethod
    async def create_new(cls, account, domains):
        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains]
        }
        resp = await account.request_signed(account.directory["newOrder"], payload)
        self = cls(account, resp.headers["Location"])
        self.raw_data = await resp.json()
        self.authorizations = [
            await Authz.create_new(auth, self)
            for auth in self.raw_data["authorizations"]
        ]
        self.status = self.raw_data["status"]
        self.identifiers = self.raw_data["identifiers"]
        self.finalize_url = self.raw_data.get("finalize", None)
        self.cert_url = self.raw_data.get("certificate", None)
        return self

    async def update(self):
        self.raw_data = await self.account.requst_unsigned(self.order_url)
        self.status = self.raw_data["status"]
        self.finalize_url = self.raw_data.get("finalize", None)
        self.cert_url = self.raw_data.get("certificate", None)

    async def finalize(self, csr):
        payload = {"csr": csr}
        resp = await self.account.request_signed(self.finalize_url, payload)
        data = await resp.json()
        self.status = data["status"]
        self.cert_url = data.get("certificate", None)

    async def download_cert(self):
        resp = await self.account.service.get_http_session().get(self.cert_url)
        if resp.status >= 200 and resp.status < 300:
            return await resp.read()
        else:
            pass  # TODO handle errors somehow


class Authz:
    def __init__(self, url, order):
        self.url = url
        self.order = order
        self.account = order.account
        self.status = None
        self.challenges = {}
        self.raw_data = None

    @classmethod
    async def create_new(cls, url, order):
        self = cls(url, order)
        self.raw_data = await self.account.requst_unsigned(self.url)
        self.challenges = {
            c["url"]: Challenge(c, self) for c in self.raw_data["challenges"]
        }
        self.status = self.raw_data["status"]
        return self

    async def update(self):
        self.raw_data = await self.account.requst_unsigned(self.url)
        self.status = self.raw_data["status"]
        for challenge in self.raw_data["challenges"]:
            self.challenges[challenge["url"]].set_data(challenge)


class Challenge:
    def __init__(self, challenge_data, authz):
        self.raw_data = challenge_data
        self.authz = authz
        self.account = authz.account
        self.type_ = challenge_data["type"]
        self.url = challenge_data["url"]
        self.status = challenge_data["status"]
        self.token = challenge_data.get("token")

    async def accept(self):
        await self.account.request_signed(self.url, {})

    def set_data(self, data):
        self.raw_data = data
        self.status = self.raw_data["status"]


class Account:
    @classmethod
    async def load(cls, keyfile, service):
        self = cls()
        self.keyfile = keyfile
        self.service = service
        self.directory = self.service.directory
        try:
            with open(self.keyfile, "rb") as f:
                self.key = load_private_key(f.read())
        except OSError:
            with open(self.keyfile, "wb") as f:
                self.key = generate_rsa_key()
                f.write(export_private_key(self.key))
        self.acct_url = None
        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:cert-admin@sampartridge.uk"],
        }
        resp = await self.request_signed(self.directory["newAccount"], payload)
        self.acct_url = resp.headers["Location"]

        return self

    def thumbprint(self):
        jwk = json.dumps(generate_jwk(self.key), sort_keys=True, separators=(",", ":"))
        thumbprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        thumbprint.update(jwk.encode("utf-8"))
        return b64(thumbprint.finalize())

    async def request_signed(self, endpoint, payload):
        log.debug("Accessing endpoint: %s", endpoint)
        nonce = await self.service.get_nonce()
        body = sign_request(self.key, endpoint, nonce, payload, self.acct_url)
        resp = await self.service.post(endpoint, body.encode("utf-8"))
        return resp

    async def requst_unsigned(self, endpoint):
        return await self.service.requst_unsigned(endpoint)


async def check_resp(resp):
    if resp.status >= 400 and resp.status < 600:
        try:
            error = await resp.json()
            code = error.get("type", None)
            message = error.get("title", "Unknown error")
            raise AcmeException(code, message)
        except ValueError:
            raise AcmeException(None, "Unknown error (no response)")


async def run(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode
