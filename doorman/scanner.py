import re
from doorman.config import GuardrailConfig
from doorman.gates.semantic import SemanticGate

class ScanVerdict:
    def __init__(self, is_flagged: bool, reason: str, confidence: float, tier: str = "AST"):
        self.is_flagged = is_flagged
        self.reason = reason
        self.confidence = confidence
        self.tier = tier


class GuardrailScanner:
    """Two-tier prompt injection guardrail scanner (Tier 1: AST, Tier 2: Semantic)."""
    
    def __init__(self, config: GuardrailConfig = None):
        self.config = config or GuardrailConfig()
        self.semantic_gate = SemanticGate()
        
        # Robust regex patterns for Tier 1 AST detection
        self.patterns = getattr(self.config, "patterns", [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"system\s+override",
            r"reveal\s+(system\s+)?passwords",
            r"unrestricted\s+mode",
            r"disregard\s+(all\s+)?prior",
            r"dump\s+the\s+database"
        ])

    def scan(self, prompt: str) -> ScanVerdict:
        if not prompt or not isinstance(prompt, str):
            return ScanVerdict(is_flagged=False, reason="Empty prompt", confidence=1.0, tier="CLEAN")

        prompt_lower = prompt.lower()

        # Tier 1: Deterministic regex pattern matching
        for pattern in self.patterns:
            if re.search(pattern, prompt_lower):
                return ScanVerdict(
                    is_flagged=True,
                    reason=f"Tier 1 AST rule matched forbidden pattern: '{pattern}'",
                    confidence=0.99,
                    tier="AST_TIER_1"
                )

        # Tier 2: Semantic embedding similarity check
        is_semantic_flagged, score, reason = self.semantic_gate.evaluate(prompt)
        if is_semantic_flagged:
            return ScanVerdict(
                is_flagged=True,
                reason=reason,
                confidence=score,
                tier="SEMANTIC_TIER_2"
            )

        return ScanVerdict(
            is_flagged=False,
            reason="Prompt passed all security gates",
            confidence=1.0,
            tier="CLEAN"
        )