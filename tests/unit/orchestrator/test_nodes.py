import pytest
from unittest.mock import patch, MagicMock

from agents.orchestrator.nodes import _persist_incident
from agents.orchestrator.state import SOCState

def test_persist_incident_exception_handling():
    """Test that _persist_incident catches exceptions during commit and logs an error."""

    state: SOCState = {
        "alert_id": "test-alert-123",
        "threat_category": "TEST",
        "severity_score": 0.5,
        "confidence_score": 0.5,
        "blast_radius": 1,
        "exposure_score": 0.5,
        "mitre_techniques": ["T1000"]
    }

    # Mock the get_session to return a mock session
    # The mock session should raise an exception on commit
    mock_session = MagicMock()
    mock_session.commit.side_effect = Exception("Database connection lost")

    # We need a context manager for get_session
    mock_get_session = MagicMock()
    mock_get_session.return_value.__enter__.return_value = mock_session

    with patch("agents.orchestrator.nodes.get_session", mock_get_session):
        with patch("agents.orchestrator.nodes.logger.error") as mock_logger_error:
            # This should not raise an exception
            _persist_incident(state, "MONITOR")

            # Verify that the session was created and commit was called
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

            # Verify that the logger logged the error
            mock_logger_error.assert_called_once()

            # Verify the exact call format: logger.error("Failed to persist incident %s: %s", state["alert_id"], exc)
            args, kwargs = mock_logger_error.call_args
            assert args[0] == "Failed to persist incident %s: %s"
            assert args[1] == "test-alert-123"
            assert str(args[2]) == "Database connection lost"
