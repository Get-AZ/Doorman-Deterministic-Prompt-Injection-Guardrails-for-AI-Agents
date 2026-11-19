def evaluate(self, prompt: str) -> dict:
    if not isinstance(prompt, str):
        raise TypeError(f"Expected prompt to be str, got {type(prompt).__name__}")

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