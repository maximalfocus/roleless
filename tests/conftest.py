from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from roleless.secure import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(str(tmp_path / "roleless.db"))
    with TestClient(app) as test_client:
        yield test_client


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
