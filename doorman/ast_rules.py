import re

# Common prompt injection patterns for Tier 1 AST / Regex inspection
SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior\s+directives",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
    r"system\s+prompt\s+override",
    r"bypass\s+safety\s+filters",
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