from doorman.ast_rules import check_ast_rules
from doorman.gates.semantic import check_semantic_gate


class DoormanGuardrail:
    def __init__(self, semantic_threshold: float = 0.85):
        self.semantic_threshold = semantic_threshold

    def evaluate(self, prompt: str) -> dict:
        """
        Evaluate a prompt across Doorman's defense tiers:
        - Tier 1: Deterministic AST / rule check
        - Tier 2: Semantic embedding / similarity gate
        """
        if check_ast_rules(prompt):
            return {
                "allowed": False,
                "tier": "tier_1_ast",
                "reason": "Matched Tier 1 deterministic rule.",
            }

        tier_2_blocked, confidence = check_semantic_gate(
            prompt, threshold=self.semantic_threshold
        )
        if tier_2_blocked:
            return {
                "allowed": False,
                "tier": "tier_2_semantic",
                "reason": f"Flagged by semantic gate with confidence {confidence:.4f}.",
            }

        return {
            "allowed": True,
            "tier": None,
            "reason": "Passed all security guardrail tiers.",
        }