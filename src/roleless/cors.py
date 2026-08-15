from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

CONSOLE_ORIGIN = "http://127.0.0.1:8080"
CONSOLE_METHODS = ["GET", "POST"]
CONSOLE_HEADERS = ["Authorization", "Content-Type", "X-Actor-Role"]


def add_console_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[CONSOLE_ORIGIN],
        allow_credentials=False,
        allow_methods=CONSOLE_METHODS,
        allow_headers=CONSOLE_HEADERS,
    )
