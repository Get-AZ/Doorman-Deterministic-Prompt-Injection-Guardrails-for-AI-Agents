from doorman.scanner import GuardrailScanner


class DoormanGuardrail:
    """Multi-tier prompt injection guardrail wrapping GuardrailScanner."""

    def __init__(self, semantic_threshold: float = 0.85, scanner: GuardrailScanner | None = None):
        self.semantic_threshold = semantic_threshold
        self.scanner = scanner if scanner is not None else GuardrailScanner()
        semantic_gate = getattr(self.scanner, "semantic_gate", None)
        if semantic_gate is not None and hasattr(semantic_gate, "threshold"):
            semantic_gate.threshold = semantic_threshold

    def evaluate(self, prompt: str) -> dict:
        verdict = self.scanner.scan(prompt)
        flagged = bool(getattr(verdict, "is_flagged", False))
        tier = getattr(verdict, "tier", None)

        return {
            "allowed": not flagged,
            "tier": tier if flagged else None,
            "reason": getattr(
                verdict,
                "reason",
                f"Flagged by {tier}." if flagged else "Passed all security guardrail tiers.",
            ),
        }