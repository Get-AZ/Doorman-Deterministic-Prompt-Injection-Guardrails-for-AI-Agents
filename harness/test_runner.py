"""
Doorman Automated Red-Team Test Runner
Executes the attack corpus against the Doorman policy engine and verifies security assertions.
"""

import json
import os
import pytest
from doorman.engine import DocumentSanitizer, DoormanPolicyEngine, SecurityException

# Load attack corpus JSON
CORPUS_PATH = os.path.join(os.path.dirname(__file__), "datasets", "attack_corpus.json")

def load_corpus():
    with open(CORPUS_PATH, "r") as f:
        return json.load(f)["test_cases"]

@pytest.fixture
def policy_engine():
    return DoormanPolicyEngine(strict_mode=True)

@pytest.mark.parametrize("test_case", load_corpus(), ids=lambda tc: tc["id"])
def test_red_team_attack_vector(policy_engine, test_case):
    """
    Automated test case verifying that Doorman intercepts and blocks 
    adversarial indirect injections and tool argument tampering attempts.
    """
    print(f"\n[RUNNING TEST] {test_case['id']}: {test_case['vector_type']}")

    # 1. Simulate document ingestion through Doorman's sanitizer (applies taint)
    sanitized_input = DocumentSanitizer.ingest_document(
        raw_text=test_case["input_payload"], 
        filename=f"resume_{test_case['id']}.pdf"
    )

    # 2. Determine target tool and arguments
    target_tool = test_case["target_tool"]
    
    # Construct args containing the tainted document or overridden parameters
    if "args_override" in test_case:
        tool_args = test_case["args_override"]
    else:
        tool_args = {"document": sanitized_input}

    # 3. Assert that the Doorman policy engine successfully blocks the attack
    if test_case["expected_outcome"] == "blocked":
        with pytest.raises(SecurityException) as exc_info:
            policy_engine.intercept_tool_call(
                tool_name=target_tool, 
                args=tool_args, 
                kwargs={}
            )
        
        # Verify the exception message contains the expected rule ID
        assert test_case["expected_rule"] in str(exc_info.value), \
            f"Expected rule {test_case['expected_rule']} not found in exception: {exc_info.value}"
        
        print(f"✅ Successfully blocked by rule: {test_case['expected_rule']}")
    else:
        # For benign inputs expected to pass
        result = policy_engine.intercept_tool_call(
            tool_name=target_tool, 
            args=tool_args, 
            kwargs={}
        )
        assert result["status"] == "allowed"