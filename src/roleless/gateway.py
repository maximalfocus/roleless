from __future__ import annotations

import httpx
from fastapi import FastAPI, Request, Response

BACKEND = "http://vulnerable:8000"
HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def fixed_backend_gateway(path: str, request: Request) -> Response:
    request_headers = {
        name: value for name, value in request.headers.items() if name.lower() not in HOP_BY_HOP
    }
    async with httpx.AsyncClient(base_url=BACKEND, timeout=10) as client:
        upstream = await client.request(
            request.method,
            f"/{path}",
            params=request.query_params,
            headers=request_headers,
            content=await request.body(),
        )
    response_headers = {
        name: value for name, value in upstream.headers.items() if name.lower() not in HOP_BY_HOP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=None,
    )
