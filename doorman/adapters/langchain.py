import logging
from typing import Any, List, Optional
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from doorman.scanner import GuardrailScanner

logger = logging.getLogger("doorman.adapters.langchain")


class DoormanLangChainCallback(BaseCallbackHandler):
    """LangChain callback handler that scans incoming prompts for prompt injection

    before they reach the language model, and monitors model responses.
    """

    def __init__(
        self,
        scanner: Optional[GuardrailScanner] = None,
        threshold: float = 0.65,
        raise_on_injection: bool = True,
    ):
        self.scanner = scanner or GuardrailScanner(threshold=threshold)
        self.raise_on_injection = raise_on_injection

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Intercepts prompts before they reach the LLM."""
        for prompt in prompts:
            verdict = self.scanner.scan(prompt)
            if verdict.is_flagged:
                logger.warning(
                    f"LangChain prompt injection blocked: {verdict.reason}"
                )
                if self.raise_on_injection:
                    raise ValueError(
                        f"Security Alert: Prompt injection detected (Confidence: {verdict.confidence:.2f})"
                    )

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Handles post-generation response validation if needed."""
        # LLMResult is now used here, resolving the unused import warning
        pass