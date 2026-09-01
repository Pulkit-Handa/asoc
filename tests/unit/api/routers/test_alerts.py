import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.routers.auth import get_current_user

def override_get_current_user():
    return {"username": "test_analyst", "role": "ANALYST"}

@pytest.fixture
def test_client():
    # Setup dependency overrides
    app.dependency_overrides[get_current_user] = override_get_current_user

    # We want to mock out things that main.py touches inside lifespan to avoid starting databases
    with patch("data.postgres.session.init_db"):
        with patch("agents.shared.embedding.warm_up"):
            with patch("agents.triage.models.SecBERTClassifier"):
                with patch("agents.forensics.clickhouse_client.init_schema"):
                    with patch("data.kafka.producer.flush"):
                        # Bypass middlewares that require external services or strict auth headers
                        with patch("api.middleware.rate_limiter.RateLimitMiddleware.dispatch", new=lambda self, request, call_next: call_next(request)):
                            with patch("api.middleware.auth.JWTAuthMiddleware.dispatch", new=lambda self, request, call_next: call_next(request)):
                                with patch("api.middleware.audit.AuditMiddleware.dispatch", new=lambda self, request, call_next: call_next(request)):
                                    with TestClient(app) as client:
                                        yield client

    # Teardown
    app.dependency_overrides.clear()

@patch("api.routers.alerts._run_pipeline")
@patch("api.routers.alerts.set_alert_id")
def test_ingest_alert_valid_payload(mock_set_alert_id, mock_run_pipeline, test_client):
    """Test successful ingestion of a valid alert payload."""
    payload = {
        "raw_log": "EventID=4624 LogonType=3 AuthPackage=NTLM user=svc_backup",
        "src_ip": "192.168.1.107",
        "user": "svc_backup",
        "host_id": "db-primary",
        "source": "manual"
    }

    response = test_client.post("/alerts", json=payload)

    assert response.status_code == 202
    data = response.json()
    assert "alert_id" in data
    assert data["alert_id"].startswith("alert_")
    assert data["status"] == "accepted"
    assert data["stream_url"] == f"/stream/{data['alert_id']}"
    assert "Subscribe to /stream/" in data["message"]

    # Assert background task was added by checking if _run_pipeline was mocked and called
    mock_run_pipeline.assert_called_once()
    mock_set_alert_id.assert_called_once()

    # Check arguments passed to _run_pipeline
    call_args = mock_run_pipeline.call_args[0]
    assert call_args[0] == data["alert_id"]
    assert call_args[1]["raw_log"] == payload["raw_log"]
    assert call_args[1]["src_ip"] == payload["src_ip"]
    assert call_args[2] == "test_analyst"

@patch("api.routers.alerts._run_pipeline")
@patch("api.routers.alerts.set_alert_id")
def test_ingest_alert_missing_raw_log(mock_set_alert_id, mock_run_pipeline, test_client):
    """Test ingestion fails with 422 if raw_log is missing."""
    payload = {
        "src_ip": "192.168.1.107",
        "user": "svc_backup"
    }

    response = test_client.post("/alerts", json=payload)

    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    # raw_log is a required field
    assert any(error["loc"] == ["body", "raw_log"] for error in data["detail"])

    # Background task should not be called
    mock_run_pipeline.assert_not_called()
    mock_set_alert_id.assert_not_called()
