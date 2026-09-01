import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from api.middleware.correlation import CorrelationMiddleware, HEADER_NAME
from agents.shared.telemetry import get_correlation_id, _user_id

app = FastAPI()

class DummyAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if "Authorization" in request.headers:
            request.state.user = "test_user_123"
        return await call_next(request)

app.add_middleware(CorrelationMiddleware)
app.add_middleware(DummyAuthMiddleware)

@app.get("/")
def read_root():
    return {
        "correlation_id": get_correlation_id(),
        "user_id": _user_id.get()
    }

client = TestClient(app)

def test_correlation_id_is_generated():
    response = client.get("/")
    assert response.status_code == 200
    assert HEADER_NAME in response.headers
    assert response.headers[HEADER_NAME].startswith("req_")

    data = response.json()
    assert data["correlation_id"] == response.headers[HEADER_NAME]

def test_correlation_id_is_honored():
    custom_id = "custom_id_123"
    response = client.get("/", headers={HEADER_NAME: custom_id})
    assert response.status_code == 200
    assert response.headers[HEADER_NAME] == custom_id

    data = response.json()
    assert data["correlation_id"] == custom_id

def test_user_id_is_injected():
    response = client.get("/", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200

    data = response.json()
    assert data["user_id"] == "test_user_123"
