import sys
import os
import argparse
from doorman.config import GuardrailConfig
from doorman.scanner import GuardrailScanner
from doorman.logger import log_security_event

def main():
    parser = argparse.ArgumentParser(description="Doorman Prompt Injection Guardrail CLI")
    parser.add_argument("prompt", type=str, help="The input prompt text to scan for injection vectors.")
    parser.add_argument("--config", type=str, default="doorman-config.json", help="Path to custom JSON configuration file.")
    
    args = parser.parse_args()
    
    # Load configuration if available in the workspace root
    config_path = args.config
    config = GuardrailConfig(config_path=config_path if os.path.exists(config_path) else None)
    
    scanner = GuardrailScanner(config=config)
    verdict = scanner.scan(args.prompt)
    
    # Record the security event to the audit log
    log_security_event(args.prompt, verdict)
    
    print("\n--- Doorman Security Scan Report ---")
    print(f"Input Text: {args.prompt}")
    print(f"Flagged:    {verdict.is_flagged}")
    print(f"Reason:     {verdict.reason}")
    print(f"Confidence: {verdict.confidence:.4f}")
    
    if verdict.is_flagged:
        sys.exit(400)
    sys.exit(0)

if __name__ == "__main__":
    main()