from __future__ import annotations

from agents.shared.telemetry import (
    set_correlation_id,
    get_correlation_id,
    set_alert_id,
    get_alert_id,
)

def test_correlation_id_getter_setter():
    set_correlation_id("corr-1234")
    assert get_correlation_id() == "corr-1234"

def test_alert_id_getter_setter():
    set_alert_id("alert-5678")
    assert get_alert_id() == "alert-5678"
