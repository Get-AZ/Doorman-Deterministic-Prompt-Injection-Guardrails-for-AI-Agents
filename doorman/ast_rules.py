import re

# Common prompt injection patterns for Tier 1 AST / Regex inspection
SUSPICIOUS_PATTERNS = [
    r"ignore previous instructions",
    r"disregard all prior directives",
    r"you are now in developer mode",
    r"system prompt override",
]

def check_ast_rules(prompt: str) -> bool:
    """
    Evaluates an incoming prompt against deterministic Tier 1 AST/regex rules.
    Returns True if a prompt injection violation is detected.
    """
    normalized_prompt = prompt.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, normalized_prompt):
            return True
    return False