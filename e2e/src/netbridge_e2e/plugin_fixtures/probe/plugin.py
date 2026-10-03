from aiohttp import web

NONCE = "__NONCE__"


async def index(request):
    return web.Response(text=f"netbridge-e2e-plugin {NONCE}")


def create_app():
    app = web.Application()
    app.router.add_get("/", index)
    return app
