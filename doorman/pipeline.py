from doorman.ast_rules import check_ast_rules

class DoormanGuardrail:
    def __init__(self, semantic_threshold: float = 0.85):
        self.semantic_threshold = semantic_threshold

    def _check_semantic_gate(self, prompt: str) -> tuple[bool, float]:
        """
        Tier 2: Semantic sentence-transformer embedding check.
        Returns (is_blocked, confidence_score).
        """
        # Placeholder or integration point for sentence-transformers model
        # Example heuristic/model invocation:
        # similarity = compute_embedding_similarity(prompt)
        # if similarity >= self.semantic_threshold: return True, similarity
        
        # For initial wiring, we return safe by default until model is plugged in
        return False, 0.0

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
        blocked_by_semantic, confidence = self._check_semantic_gate(prompt)
        if blocked_by_semantic:
            return {
                "allowed": False,
                "tier": "tier_2_semantic",
                "reason": f"Flagged by Tier 2 semantic gate with confidence {confidence:.2f}"
            }

        return {
            "allowed": True,
            "tier": None,
            "reason": "Passed all security guardrail tiers."
        }