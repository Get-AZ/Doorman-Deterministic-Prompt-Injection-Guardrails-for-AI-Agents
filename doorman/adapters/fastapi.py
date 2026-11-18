import os
import json
from functools import wraps
from fastapi import FastAPI, HTTPException, status, Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from doorman.config import GuardrailConfig
from doorman.scanner import GuardrailScanner
from doorman.logger import log_security_event

app = FastAPI(title="Doorman Prompt Injection Guardrail API", version="0.1.0")

# Load configuration and initialize scanner on application startup
config_path = "doorman-config.json"
config = GuardrailConfig(config_path=config_path if os.path.exists(config_path) else None)
scanner = GuardrailScanner(config=config)

class PromptRequest(BaseModel):
    prompt: str = None
    query: str = None
    text: str = None


class PromptGuard:
    """Programmatic guard utility and FastAPI callable dependency for validating prompts."""
    def __init__(self, scanner_instance=None):
        self.scanner = scanner_instance or scanner

    def check(self, prompt: str):
        return self.scanner.scan(prompt)

    def __call__(self, prompt: str = None):
        return self


def protect_prompt(field_name: str = "prompt"):
    """
    Supports being used as a decorator: @protect_prompt(field_name="query")
    or as a direct function call: protect_prompt("some prompt text")
    """
    if isinstance(field_name, str) and (" " in field_name or len(field_name) > 30 or not field_name.isidentifier()):
        prompt = field_name
        verdict = scanner.scan(prompt)
        log_security_event(prompt, verdict)
        if verdict.is_flagged:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Prompt injection detected",
                    "reason": verdict.reason,
                    "confidence": verdict.confidence
                }
            )
        return verdict

    actual_field = field_name if isinstance(field_name, str) else "prompt"

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for arg in list(args) + list(kwargs.values()):
                if hasattr(arg, "model_dump") and callable(arg.model_dump):
                    data = arg.model_dump()
                elif hasattr(arg, "dict") and callable(arg.dict):
                    data = arg.dict()
                else:
                    data = None

                if data and isinstance(data, dict):
                    text = data.get(actual_field) or data.get("prompt") or data.get("query") or data.get("text")
                    if text and isinstance(text, str):
                        verdict = scanner.scan(text)
                        log_security_event(text, verdict)
                        if verdict.is_flagged:
                            raise HTTPException(
                                status_code=400,
                                detail={
                                    "error": "Prompt injection detected",
                                    "reason": verdict.reason,
                                    "confidence": verdict.confidence
                                }
                            )
            return await func(*args, **kwargs)
        return wrapper

    return decorator


class DoormanMiddleware(BaseHTTPMiddleware):
    """Starlette BaseHTTPMiddleware to intercept and inspect requests for prompt injection."""
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT"]:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    async def receive() -> dict:
                        return {"type": "http.request", "body": body_bytes}
                    request._receive = receive
                    request._body = body_bytes

                    try:
                        body_data = json.loads(body_bytes)
                        if isinstance(body_data, dict):
                            prompt_text = body_data.get("prompt") or body_data.get("text") or body_data.get("query")
                            if prompt_text and isinstance(prompt_text, str):
                                verdict = scanner.scan(prompt_text)
                                log_security_event(prompt_text, verdict)
                                if verdict.is_flagged:
                                    return JSONResponse(
                                        status_code=400,
                                        content={
                                            "detail": {
                                                "error": "Prompt injection detected",
                                                "reason": verdict.reason,
                                                "confidence": verdict.confidence
                                            }
                                        }
                                    )
                    except Exception:
                        pass
            except Exception:
                pass

        return await call_next(request)


app.add_middleware(DoormanMiddleware)


@app.post("/scan", status_code=status.HTTP_200_OK)
async def scan_prompt(request: PromptRequest):
    text = request.prompt or request.query or request.text
    verdict = scanner.scan(text or "")
    log_security_event(text or "", verdict)
    
    if verdict.is_flagged:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Prompt injection detected",
                "reason": verdict.reason,
                "confidence": verdict.confidence
            }
        )
        
    return {
        "status": "clean",
        "is_flagged": False,
        "confidence": verdict.confidence
    }


@app.post("/api/recruit", status_code=status.HTTP_200_OK)
@protect_prompt(field_name="prompt")
async def api_recruit(request: PromptRequest):
    text = request.prompt or request.query or request.text
    verdict = scanner.scan(text or "")
    log_security_event(text or "", verdict)
    if verdict.is_flagged:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Prompt injection detected",
                "reason": verdict.reason,
                "confidence": verdict.confidence
            }
        )
    return {"status": "success"}


@app.post("/api/secure-chat", status_code=status.HTTP_200_OK)
@protect_prompt(field_name="query")
async def api_secure_chat(request: PromptRequest):
    text = request.query or request.prompt or request.text
    verdict = scanner.scan(text or "")
    log_security_event(text or "", verdict)
    if verdict.is_flagged:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Prompt injection detected",
                "reason": verdict.reason,
                "confidence": verdict.confidence
            }
        )
    return {"status": "success"}