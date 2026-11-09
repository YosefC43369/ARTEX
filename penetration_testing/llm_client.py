"""
penetration_testing.llm_client
===============================

Thin OpenRouter adapter for the subsystem.

ARTEX does **not** expose a single shared LLM client class — every existing
``modules/AI_*.py`` embeds its own ``_call_openrouter`` helper with identical
wiring (same endpoint, env var, model, bearer auth, retry/backoff). Rather than
add a *second, divergent* provider configuration, this adapter reproduces that
exact convention in one reusable place and reads the same ``OPENROUTER_API_KEY``
environment variable.

The client is **optional**: with no API key it reports ``available == False``
and callers fall back to deterministic logic, mirroring the "rule-based
fallback" pattern already used throughout ARTEX. This means the subsystem is
fully functional (just non-AI-assisted) without a key, and never blocks on the
network for core operation.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import requests

from .constants import (
    DEFAULT_OPENROUTER_MODEL,
    DEFAULT_OPENROUTER_URL,
    OPENROUTER_API_KEY_ENV,
)
from .exceptions import LLMError


class OpenRouterClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        model: str = DEFAULT_OPENROUTER_MODEL,
        url: str = DEFAULT_OPENROUTER_URL,
        timeout: int = 45,
        max_retries: int = 3,
        logger: Optional[logging.Logger] = None,
    ):
        # Fall back to the shared ARTEX env var so a single key configures both
        # the existing modules and this subsystem.
        self.api_key = api_key or os.getenv(OPENROUTER_API_KEY_ENV, "")
        self.model = model
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logger or logging.getLogger(__name__)

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 1500,
    ) -> Optional[str]:
        """Return the model's text, or ``None`` if unavailable/unrecoverable.

        Callers treat ``None`` as "fall back to deterministic logic", so this
        never raises for the common no-key / transient-failure cases. It raises
        :class:`LLMError` only for a programming error (empty prompt).
        """
        if not prompt or not prompt.strip():
            raise LLMError("Refusing to call OpenRouter with an empty prompt.")
        if not self.available:
            self.logger.debug("OpenRouter key absent — using deterministic path.")
            return None

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        for attempt in range(self.max_retries):
            try:
                resp = requests.post(
                    self.url, headers=headers, json=payload, timeout=self.timeout
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    wait = 10 * (attempt + 1)
                    self.logger.warning("OpenRouter rate-limited; waiting %ss", wait)
                    time.sleep(wait)
                    continue
                self.logger.error(
                    "OpenRouter returned %s: %s", resp.status_code, resp.text[:200]
                )
                return None
            except requests.exceptions.Timeout:
                self.logger.warning("OpenRouter timeout (attempt %s)", attempt + 1)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
            except Exception as exc:  # network / JSON shape / etc.
                self.logger.error("OpenRouter request error: %s", exc)
                return None
        return None
