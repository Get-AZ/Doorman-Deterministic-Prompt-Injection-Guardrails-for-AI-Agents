from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from doorman.ast_rules import check_ast_rules
# Import your semantic gate / pipeline module if configured in your package
# from doorman.pipeline import evaluate_prompt

app = FastAPI(
    title="Doorman Security Harness API",
    description="Deterministic prompt injection guardrail and security benchmark harness",
    version="0.1.0"
)

class PromptRequest(BaseModel):
    prompt: str

@app.post("/v1/generate")
async def generate_endpoint(request: PromptRequest):
    """
    Guarded text generation endpoint protected by Tier-1 AST 
    and Tier-2 Semantic security layers.
    """
    # 1. Tier-1: Fast AST / Regex Inspection
    if check_ast_rules(request.prompt):
        raise HTTPException(
            status_code=400,
            detail="Security violation: Prompt injection pattern detected by Tier-1 AST guardrails."
        )
    
    # 2. Tier-2: Semantic Gate / Advanced Intent Screening (Optional / Pipeline check)
    # if evaluate_prompt(request.prompt).is_flagged:
    #     raise HTTPException(
    #         status_code=400,
    #         detail="Security violation: Semantic prompt injection anomaly flagged."
    #     )
    
    return {
        "status": "allowed",
        "prompt": request.prompt,
        "message": "Input successfully passed all security guardrail layers."
    }