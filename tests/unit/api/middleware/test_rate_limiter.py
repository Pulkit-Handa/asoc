import pytest
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.middleware.rate_limiter import RateLimitMiddleware

app = FastAPI()
app.add_middleware(RateLimitMiddleware, max_requests=2, window_seconds=60)

@app.get("/")
def read_root():
    return {"message": "ok"}

@app.get("/health")
def read_health():
    return {"status": "up"}

client = TestClient(app)

def test_skip_paths_bypasses_rate_limit():
    with patch("api.middleware.rate_limiter._get_redis") as mock_get_redis:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "up"}
        mock_get_redis.assert_not_called()

def test_rate_limit_allowed():
    with patch("api.middleware.rate_limiter._get_redis") as mock_get_redis:
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        mock_redis.eval.return_value = [1, 1]

        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "ok"}

def test_rate_limit_exceeded():
    with patch("api.middleware.rate_limiter._get_redis") as mock_get_redis:
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        mock_redis.eval.return_value = [0, 2]

        response = client.get("/")
        assert response.status_code == 429
        assert response.json() == {
            "detail": "Rate limit exceeded: 2 requests per 60s",
            "current": 2,
            "limit": 2
        }
        assert response.headers["Retry-After"] == "60"

def test_redis_failure_fails_open():
    with patch("api.middleware.rate_limiter._get_redis") as mock_get_redis:
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        mock_redis.eval.side_effect = Exception("Redis is down")

        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "ok"}
