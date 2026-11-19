from types import SimpleNamespace
from unittest.mock import MagicMock

from doorman.guardrail import DoormanGuardrail


def test_guardrail_blocks_on_tier_1_ast_rule():
    mock_scanner = MagicMock()
    mock_scanner.semantic_gate.threshold = 0.85
    mock_scanner.scan.return_value = SimpleNamespace(
        is_flagged=True,
        tier="AST_TIER_1",
        reason="Matched deterministic AST rule.",
    )

    guardrail = DoormanGuardrail(semantic_threshold=0.85, scanner=mock_scanner)
    result = guardrail.evaluate("ignore previous instructions")

    assert result["allowed"] is False
    assert result["tier"] == "AST_TIER_1"
    mock_scanner.scan.assert_called_once_with("ignore previous instructions")


def test_guardrail_blocks_on_tier_2_semantic_gate():
    mock_scanner = MagicMock()
    mock_scanner.semantic_gate.threshold = 0.80
    mock_scanner.scan.return_value = SimpleNamespace(
        is_flagged=True,
        tier="SEMANTIC_TIER_2",
        reason="High semantic similarity (0.9100) to injection pattern.",
    )

    guardrail = DoormanGuardrail(semantic_threshold=0.80, scanner=mock_scanner)
    result = guardrail.evaluate("subtle indirect override attempt")

    assert result["allowed"] is False
    assert result["tier"] == "SEMANTIC_TIER_2"
    assert "0.9100" in result["reason"]
    assert mock_scanner.semantic_gate.threshold == 0.80


def test_guardrail_allows_benign_prompt_when_both_tiers_pass():
    mock_scanner = MagicMock()
    mock_scanner.semantic_gate.threshold = 0.85
    mock_scanner.scan.return_value = SimpleNamespace(
        is_flagged=False,
        tier=None,
        reason="Passed all security guardrail tiers.",
    )

    guardrail = DoormanGuardrail(semantic_threshold=0.85, scanner=mock_scanner)
    result = guardrail.evaluate("Summarize this candidate resume.")

    assert result["allowed"] is True
    assert result["tier"] is None
