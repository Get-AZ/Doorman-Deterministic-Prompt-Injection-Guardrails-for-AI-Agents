import json
import os
from datetime import datetime, timezone

LOG_FILE = os.getenv("DOORMAN_LOG_FILE", "doorman-audit.jsonl")

def log_security_event(prompt: str, verdict):
    """Logs security scan verdicts to a JSONL audit trail file."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
        "is_flagged": verdict.is_flagged,
        "reason": verdict.reason,
        "confidence": verdict.confidence,
        "tier": getattr(verdict, "tier", "UNKNOWN")
    }
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        # Fallback or silent catch to prevent logging I/O failures from breaking app execution
        pass