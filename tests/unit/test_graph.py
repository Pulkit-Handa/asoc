"""
Unit tests for the orchestrator graph.
"""
import sys
from unittest.mock import MagicMock

sys.modules["agents.triage"] = MagicMock()
sys.modules["agents.triage.agent"] = MagicMock()
sys.modules["agents.forensics"] = MagicMock()
sys.modules["agents.forensics.agent"] = MagicMock()
sys.modules["agents.blast_radius"] = MagicMock()
sys.modules["agents.blast_radius.agent"] = MagicMock()
sys.modules["agents.critic"] = MagicMock()
sys.modules["agents.critic.agent"] = MagicMock()
sys.modules["agents.orchestrator.nodes"] = MagicMock()

# Mock out StateGraph to avoid ValueError
import langgraph.graph
class MockStateGraph:
    def __init__(self, *args, **kwargs):
        pass
    def add_node(self, *args, **kwargs):
        pass
    def set_entry_point(self, *args, **kwargs):
        pass
    def add_conditional_edges(self, *args, **kwargs):
        pass
    def add_edge(self, *args, **kwargs):
        pass
    def compile(self, *args, **kwargs):
        return MagicMock()

langgraph.graph.StateGraph = MockStateGraph

from agents.orchestrator.graph import risk_gate, CONFIDENCE_THRESHOLD

class TestRiskGate:
    def test_risk_gate_below_threshold(self):
        state = {"alert_id": "alert-1", "confidence_score": CONFIDENCE_THRESHOLD - 0.1}
        result = risk_gate(state)
        assert result == "escalate"

    def test_risk_gate_above_or_equal_threshold(self):
        state = {"alert_id": "alert-2", "confidence_score": CONFIDENCE_THRESHOLD}
        result = risk_gate(state)
        assert result == "forensics"

        state2 = {"alert_id": "alert-3", "confidence_score": CONFIDENCE_THRESHOLD + 0.1}
        result2 = risk_gate(state2)
        assert result2 == "forensics"

    def test_risk_gate_missing_confidence(self):
        # Missing confidence defaults to 0.0 which is < CONFIDENCE_THRESHOLD
        state = {"alert_id": "alert-4"}
        result = risk_gate(state)
        assert result == "escalate"
