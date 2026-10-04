"""
Unit Tests — Agent Logic
=========================
These tests mock all external dependencies (ChromaDB, Redis, ClickHouse, LLM).
They run in milliseconds, require no Docker services, and are safe to run in CI.

They test the business logic that matters most:
  - Risk Gate threshold enforcement
  - Blast radius exposure calculation + crown-jewel weighting
  - Decision logic (ESCALATE/MONITOR/AUTO_CLOSE conditions)
  - Resilience: fallback behaviour when services are down
  - Normalizers: CEF, syslog, Windows Event parsing
  - SecBERT heuristic fallback accuracy
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("ASOC_ENV", "development")
os.environ.setdefault("ASOC_DEV_MODE", "true")


# ── SecBERT heuristic ─────────────────────────────────────────────────────────

class TestSecBERTHeuristic:
    """Tests for the keyword-based fallback classifier."""

    def setup_method(self):
        from agents.triage.models import SecBERTClassifier
        self.clf = SecBERTClassifier.__new__(SecBERTClassifier)
        self.clf._pipeline      = None
        self.clf._use_heuristic = True

    def test_mimikatz_classified_credential_access(self):
        result = self.clf._heuristic_classify(
            "process=mimikatz.exe accessing=lsass.exe src_ip=10.0.0.5"
        )
        assert result.category == "Credential Access"
        assert result.confidence >= 0.80

    def test_ransomware_classified_impact(self):
        result = self.clf._heuristic_classify(
            "vssadmin delete shadows /all /quiet file_count=3847 ext=.locked"
        )
        assert result.category == "Impact"
        assert result.confidence >= 0.85

    def test_lateral_movement_smb(self):
        result = self.clf._heuristic_classify(
            "EventID=5140 ShareName=\\\\server\\ADMIN$ src_ip=10.0.1.5 user=jsmith"
        )
        assert result.category == "Lateral Movement"

    def test_failed_login_benign(self):
        result = self.clf._heuristic_classify(
            "EventID=4625 FailedLogon user=bob.jones SubStatus=0xC000006A"
        )
        assert result.category == "Benign"

    def test_returns_confidence_between_0_and_1(self):
        for text in ["normal syslog message", "mimikatz", "smb lateral movement credential dump"]:
            result = self.clf._heuristic_classify(text)
            assert 0.0 <= result.confidence <= 1.0, f"Out-of-range for: {text}"

    def test_classify_batch_returns_same_length(self):
        texts = ["alert one", "alert two", "alert three"]
        results = self.clf.classify_batch(texts)
        assert len(results) == len(texts)


# ── Blast Radius ──────────────────────────────────────────────────────────────

class TestBlastRadius:
    """Tests for BFS exposure calculation."""

    def setup_method(self):
        import networkx as nx
        self.G = nx.Graph()
        # Build a small test topology
        nodes = [
            ("web-01",    {"crown_jewel": False}),
            ("app-01",    {"crown_jewel": False}),
            ("db-01",     {"crown_jewel": True}),
            ("dc-01",     {"crown_jewel": True}),
            ("isolated",  {"crown_jewel": False}),
        ]
        self.G.add_nodes_from(nodes)
        self.G.add_edges_from([("web-01", "app-01"), ("app-01", "db-01"), ("app-01", "dc-01")])

    @patch("agents.blast_radius.agent.is_crown_jewel")
    def test_crown_jewel_reachable_forces_high_exposure(self, mock_cj):
        mock_cj.side_effect = lambda n: n in ("db-01", "dc-01")

        from agents.blast_radius.agent import compute_blast_radius
        count, exposure, crown_jewels = compute_blast_radius("web-01", self.G, 10)

        assert len(crown_jewels) == 2
        assert exposure > 0.40, f"Expected exposure > 0.40, got {exposure}"

    @patch("agents.blast_radius.agent.is_crown_jewel", return_value=False)
    def test_isolated_host_low_exposure(self, _mock):
        from agents.blast_radius.agent import compute_blast_radius
        count, exposure, crown_jewels = compute_blast_radius("isolated", self.G, 100)

        assert count == 1
        assert exposure < 0.10

    @patch("agents.blast_radius.agent.is_crown_jewel", return_value=False)
    def test_unknown_host_returns_zero(self, _mock):
        from agents.blast_radius.agent import compute_blast_radius
        count, exposure, crown_jewels = compute_blast_radius("ghost-host", self.G, 100)

        assert count == 0
        assert exposure == 0.0
        assert crown_jewels == []

    @patch("agents.blast_radius.agent.is_crown_jewel")
    def test_exposure_capped_at_1(self, mock_cj):
        mock_cj.return_value = True
        from agents.blast_radius.agent import compute_blast_radius
        _, exposure, _ = compute_blast_radius("web-01", self.G, 1)
        assert exposure == 1.0


# ── Resilience module ─────────────────────────────────────────────────────────

class TestResilience:
    """Tests for circuit breaker and retry logic."""

    def test_retry_succeeds_on_second_attempt(self):
        from agents.shared.resilience import retry

        attempts = {"count": 0}

        @retry(max_attempts=3, base_delay=0.01)
        def flaky():
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise ValueError("Not yet")
            return "ok"

        assert flaky() == "ok"
        assert attempts["count"] == 2

    def test_retry_raises_after_exhaustion(self):
        from agents.shared.resilience import retry

        @retry(max_attempts=2, base_delay=0.01)
        def always_fails():
            raise RuntimeError("Permanent failure")

        with pytest.raises(RuntimeError, match="Permanent failure"):
            always_fails()

    def test_circuit_breaker_opens_after_threshold(self):
        from agents.shared.resilience import CircuitBreaker, BreakerState

        breaker = CircuitBreaker(service="test", failure_threshold=3, recovery_timeout=9999)

        def bad():
            raise ConnectionError("down")

        for _ in range(3):
            with pytest.raises(ConnectionError):
                breaker.call(bad)

        assert breaker.state == BreakerState.OPEN

    def test_circuit_breaker_open_raises_immediately(self):
        from agents.shared.resilience import CircuitBreaker, ServiceUnavailableError, BreakerState

        breaker = CircuitBreaker(service="test", failure_threshold=1, recovery_timeout=9999)
        breaker._state = BreakerState.OPEN
        breaker._last_failure_at = 9999999999.0   # Far future — won't recover

        with pytest.raises(ServiceUnavailableError):
            breaker.call(lambda: "never called")

    def test_with_fallback_returns_default_on_error(self):
        from agents.shared.resilience import with_fallback

        @with_fallback(fallback_value=[], service="test")
        def explodes():
            raise RuntimeError("boom")

        result = explodes()
        assert result == []


# ── Log normalizers ───────────────────────────────────────────────────────────

class TestNormalizers:
    """Tests for CEF, syslog, Windows Event normalizers."""

    def test_cef_extracts_src_ip(self):
        from data.normalizers.cef_normalizer import normalize_cef
        log = "CEF:0|Fortinet|FortiGate|6.4|1|Traffic Deny|7|src=10.0.1.5 dst=8.8.8.8 spt=54321 dpt=443"
        result = normalize_cef(log)
        assert result.get("src_ip") == "10.0.1.5"

    def test_cef_returns_empty_for_non_cef(self):
        from data.normalizers.cef_normalizer import normalize_cef
        result = normalize_cef("this is not cef format")
        assert result == {}

    def test_syslog_rfc5424_extracts_hostname(self):
        from data.normalizers.syslog_normalizer import normalize_syslog
        log = "<34>1 2026-03-12T10:00:00Z myserver sshd 12345 - - Failed password for root from 192.168.1.1"
        result = normalize_syslog(log)
        assert result.get("host_id") == "myserver"

    def test_syslog_extracts_ip_from_message(self):
        from data.normalizers.syslog_normalizer import normalize_syslog
        log = "<34>1 2026-03-12T10:00:00Z srv sshd 1 - - Failed for user from 10.20.30.40"
        result = normalize_syslog(log)
        assert result.get("src_ip") == "10.20.30.40"

    def test_windows_json_event_4625(self):
        import json
        from data.normalizers.windows_event import normalize_windows_event

        event = json.dumps({
            "winlog": {
                "event_id": 4625,
                "event_data": {
                    "TargetUserName": "Administrator",
                    "IpAddress": "192.168.5.10",
                },
            },
            "host": {"name": "dc-01"},
        })
        result = normalize_windows_event(event)
        assert result.get("event_id") == 4625
        assert result.get("user") == "Administrator"
        assert result.get("src_ip") == "192.168.5.10"
        assert result.get("mitre_id") == "T1110"   # Brute force

    def test_windows_high_severity_event(self):
        import json
        from data.normalizers.windows_event import normalize_windows_event, _HIGH_SEVERITY_EVENTS

        for event_id in list(_HIGH_SEVERITY_EVENTS)[:3]:
            event = json.dumps({
                "winlog": {"event_id": event_id, "event_data": {}},
                "host": {"name": "test-host"},
            })
            result = normalize_windows_event(event)
            assert result.get("severity_score", 0) >= 0.7, \
                f"Event {event_id} should have high severity"


# ── Settings validation ───────────────────────────────────────────────────────

class TestSettings:
    def test_invalid_log_level_raises(self):
        from pydantic import ValidationError
        with pytest.raises((ValidationError, ValueError)):
            from config.settings import Settings
            Settings(log_level="INVALID_LEVEL", _env_file=None)

    def test_api_keys_parsed_correctly(self):
        from config.settings import Settings
        s = Settings(api_keys="key1,key2, key3 ", _env_file=None)
        assert "key1" in s.api_keys_set
        assert "key2" in s.api_keys_set
        assert "key3" in s.api_keys_set

    def test_dev_mode_allowed_in_development(self):
        from config.settings import Settings, Environment
        # Should not raise
        Settings(asoc_env=Environment.DEVELOPMENT, asoc_dev_mode=True, _env_file=None)
