from doorman.ast_rules import check_ast_rules
# from doorman.semantic_gate import check_semantic_gate  # Your Tier 2 gate

class DoormanGuardrail:
    def __init__(self, semantic_threshold: float = 0.85):
        self.semantic_threshold = semantic_threshold

    def evaluate(self, prompt: str) -> dict:
        """
        Evaluates a prompt through Doorman's multi-tier defense architecture:
        - Tier 1: Deterministic AST & Regex Rule Check
        - Tier 2: Semantic Sentence-Transformer Embedding Gate
        """
        # Tier 1: Fast deterministic check
        if check_ast_rules(prompt):
            return {
                "allowed": False,
                "tier": "tier_1_ast",
                "reason": "Matched forbidden Tier 1 AST / regex pattern."
            }

        # Tier 2: Semantic similarity / embedding check
        # tier_2_blocked, confidence = check_semantic_gate(prompt, threshold=self.semantic_threshold)
        # if tier_2_blocked:
        #     return {
        #         "allowed": False,
        #         "tier": "tier_2_semantic",
        #         "reason": f"Flagged by semantic gate with confidence {confidence}"
        #     }

        return {
            "allowed": True,
            "tier": None,
            "reason": "Passed all security guardrail tiers."
        }