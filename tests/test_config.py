import os
import json
import pytest
from doorman.config import GuardrailConfig

def test_guardrail_config_loading(tmp_path):
    # Create a temporary config file
    config_file = tmp_path / "test-config.json"
    config_data = {
        "threshold": 0.80,
        "keywords": ["custom malformed keyword"],
        "regex_patterns": ["(?i)test\\s*regex"]
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    
    # Load configuration
    cfg = GuardrailConfig(config_path=str(config_file))
    
    assert cfg.threshold == 0.80
    assert "custom malformed keyword" in cfg.custom_keywords
    assert "(?i)test\\s*regex" in cfg.custom_regex

def test_guardrail_config_fallback():
    # Test handling of non-existent config files gracefully
    cfg = GuardrailConfig(config_path="non_existent_file_xyz.json")
    assert cfg.threshold == 0.65  # Default fallback threshold
    assert cfg.custom_keywords == []