from samp20.asyncservice.httpserver import HttpServer
from aiohttp import web
import asyncio

WELL_KNOWN = ('/', '.well-known','acme-challenge')

class HttpVerifier(HttpServer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pending_auths = {}

    async def handle_request(self, request):
        parts = request.url.parts
        well_known_len = len(WELL_KNOWN)
        if len(parts) != well_known_len + 1:
            raise web.HTTPForbidden()
    
        if parts[:well_known_len] != WELL_KNOWN:
            raise web.HTTPForbidden()

        token = parts[well_known_len]
        try:
            auth = self.pending_auths[token]
            auth[1].set_result(None)
            return web.Response(text=auth[0])
        except KeyError:
            raise web.HTTPForbidden()

        request.url.path == WELL_KNOWN + auth['token']

    def can_process(self, challenge):
        return challenge.type_ == 'http-01'

    async def process_challenge(self, challenge, thumbprint):
        try:
            key_auth = challenge.token + '.' + thumbprint
            future = asyncio.get_running_loop().create_future()
            self.pending_auths[challenge.token] = (key_auth, future)
            await future
        finally:
            del self.pending_auths[challenge.token]