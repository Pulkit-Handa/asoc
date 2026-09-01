import json
import logging
import sys
from datetime import datetime, timezone

from agents.shared.telemetry import (
    JSONLogFormatter,
    set_correlation_id,
    set_alert_id,
    set_user_id,
)


def test_json_log_formatter_basic():
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    # We need to manually set module and funcName because LogRecord doesn't
    # strictly require them in constructor in the exact way we might expect for all versions,
    # but actually LogRecord initializes them based on pathname etc, let's just let it do its thing.

    formatted_str = formatter.format(record)
    log_obj = json.loads(formatted_str)

    assert "timestamp" in log_obj
    assert log_obj["level"] == "INFO"
    assert log_obj["logger"] == "test_logger"
    assert log_obj["message"] == "Test message"
    assert log_obj["service"] == "asoc"
    assert "module" in log_obj
    assert "function" in log_obj
    assert log_obj["line"] == 42

    # Check that context variables are NOT present by default
    assert "correlation_id" not in log_obj
    assert "alert_id" not in log_obj
    assert "user_id" not in log_obj


def test_json_log_formatter_with_context():
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    set_correlation_id("test-corr-id")
    set_alert_id("test-alert-id")
    set_user_id("test-user-id")

    formatted_str = formatter.format(record)
    log_obj = json.loads(formatted_str)

    assert log_obj["correlation_id"] == "test-corr-id"
    assert log_obj["alert_id"] == "test-alert-id"
    assert log_obj["user_id"] == "test-user-id"

    # Clear context vars so it doesn't affect other tests (or they'll run in the same context)
    set_correlation_id("")
    set_alert_id("")
    set_user_id("")


def test_json_log_formatter_with_exception():
    formatter = JSONLogFormatter()

    exc_info = None
    try:
        1 / 0
    except ZeroDivisionError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test_logger",
        level=logging.ERROR,
        pathname="test_file.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=exc_info,
    )

    formatted_str = formatter.format(record)
    log_obj = json.loads(formatted_str)

    assert "exception" in log_obj
    assert log_obj["exception"]["type"] == "ZeroDivisionError"
    assert "division by zero" in log_obj["exception"]["message"].lower()
    assert isinstance(log_obj["exception"]["stack"], list)
    assert len(log_obj["exception"]["stack"]) > 0


def test_json_log_formatter_with_extra_fields():
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    # Simulate extra fields passed via extra={"custom_field": "custom_value", "another_field": 123}
    record.__dict__["custom_field"] = "custom_value"
    record.__dict__["another_field"] = 123
    # Also simulate a private field
    record.__dict__["_private_field"] = "hidden"

    formatted_str = formatter.format(record)
    log_obj = json.loads(formatted_str)

    # Extra fields should be at the root
    assert log_obj["custom_field"] == "custom_value"
    assert log_obj["another_field"] == 123

    # Private field should be ignored
    assert "_private_field" not in log_obj

    # Built-in properties like name, msg, args should not be duplicated as custom fields
    # (they are mapped to logger, message respectively, but original names shouldn't be present)
    assert "name" not in log_obj
    assert "msg" not in log_obj
    assert "args" not in log_obj
