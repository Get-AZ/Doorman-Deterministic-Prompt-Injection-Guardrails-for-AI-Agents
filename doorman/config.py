import json
import os
from pathlib import Path

class GuardrailConfig:
    def __init__(self, config_path: str = None):
        self.custom_keywords = []
        self.custom_regex = []
        self.threshold = 0.65
        
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)

    def load_config(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.custom_keywords = data.get("keywords", [])
            self.custom_regex = data.get("regex_patterns", [])
            self.threshold = data.get("threshold", 0.65)