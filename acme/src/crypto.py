import json
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
    RSAPrivateKey
)

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes

def b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


def generate_rsa_key(size=4096):
    return generate_private_key(65537, size, default_backend())


def load_private_key(data):
    key = load_pem_private_key(data, password=None, backend=default_backend())
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("Key is not a private RSA key.")
    elif isinstance(key, RSAPrivateKey) and key.key_size < 2048:
        raise ValueError("The key must be 2048 bits or longer.")
    return key


def export_private_key(key):
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


def generate_jwk(key):
    numbers = key.public_key().public_numbers()
    e = numbers.e.to_bytes((numbers.e.bit_length() // 8 + 1), byteorder='big')
    n = numbers.n.to_bytes((numbers.n.bit_length() // 8 + 1), byteorder='big')
    if n[0] == 0:
        n = n[1:]
    return {
        'e': b64(e),
        'kty': 'RSA',
        'n': b64(n)
    }


def sign_request(key, endpoint, nonce, payload, acct_url=None):
    header = {'alg': 'RS256'}
    if acct_url is not None:
        header['kid'] = acct_url
    else:
        header['jwk'] = generate_jwk(key)
    header['nonce'] = nonce
    header['url'] = endpoint

    protected = b64(json.dumps(header).encode('utf-8'))
    payload = b64(json.dumps(payload).encode('utf-8'))

    signature = key.sign((protected+'.'+payload).encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())

    return json.dumps({
        'protected': protected,
        'payload': payload,
        'signature': b64(signature)
    })


def create_csr(key, domains, must_staple=False):
    assert domains

    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains])
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).add_extension(san, critical=False)

    if must_staple:
        oscp_must_staple = x509.TLSFeature(features=[x509.TLSFeatureType.status_request])
        csr.add_extension(oscp_must_staple, critical=False)
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return export_csr_for_acme(csr)


def export_csr_for_acme(csr):
    return b64(csr.public_bytes(Encoding.DER))