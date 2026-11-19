from __future__ import annotations

from typing import Any

from doorman.scanner import GuardrailScanner


class DoormanGuardrail:
    """High-level guardrail facade delegating evaluation to GuardrailScanner."""

    def __init__(
        self,
        semantic_threshold: float | None = None,
        scanner: GuardrailScanner | Any | None = None,
    ) -> None:
        self.scanner = scanner if scanner is not None else GuardrailScanner()
        self.semantic_threshold = semantic_threshold

        if semantic_threshold is not None:
            gate = getattr(self.scanner, "semantic_gate", None)
            if gate is not None and hasattr(gate, "threshold"):
                gate.threshold = semantic_threshold

    def evaluate(self, prompt: str) -> dict[str, Any]:
        if not isinstance(prompt, str):
            raise TypeError(f"Expected prompt to be str, got {type(prompt).__name__}")

        verdict = self.scanner.scan(prompt)
        flagged = bool(getattr(verdict, "is_flagged", False))
        tier = getattr(verdict, "tier", None)
        default_reason = (
            f"Flagged by {tier}." if flagged else "Passed all security guardrail tiers."
        )
        reason = getattr(verdict, "reason", default_reason)

        return {
            "allowed": not flagged,
            "tier": tier if flagged else None,
            "reason": reason,
        }