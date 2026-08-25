"""
nvidia_nim_client.py — Shared LLM interface for all three agents with automatic Model Failover.
Talks to NVIDIA NIM API (hosted or local) and falls back to alternate models if one fails.
"""

import os
import json
import time
import logging
import requests

logger = logging.getLogger(__name__)

# Verified and active models with fast response times on integrate.api.nvidia.com
DEFAULT_FALLBACK_MODELS = [
    "meta/llama-3.1-8b-instruct",
    "meta/llama-3.1-70b-instruct",
    "meta/llama-3.2-3b-instruct",
    "meta/llama-3.2-11b-vision-instruct",
    "meta/llama-3.2-1b-instruct",
]


class NvidiaNimClient:
    """
    Wraps the NVIDIA NIM REST API (OpenAI-compatible) with automatic model fallback.
    All agents share one instance of this class.

    For hosted NIM, use: https://integrate.api.nvidia.com/v1
    For local NIM, use: http://localhost:8000/v1
    """

    def __init__(
        self,
        base_url: str = "https://integrate.api.nvidia.com/v1",
        model: str = "meta/llama-3.1-8b-instruct",
        api_key: str = None,
        fallback_models: list[str] = None,
    ):
        if not api_key:
            api_key = os.getenv("NVIDIA_NIM_KEY") or os.getenv("NVIDIA_API_KEY")
        
        self.base_url = base_url.rstrip("/")
        self.model = model or "meta/llama-3.1-8b-instruct"
        self.api_key = api_key.strip() if api_key else None

        # Build candidate model list with primary first, followed by unique fallbacks
        fallbacks = fallback_models or DEFAULT_FALLBACK_MODELS
        self.candidate_models = [self.model] + [m for m in fallbacks if m != self.model]

        if not self.api_key:
            logger.info("[NvidiaNimClient] No NVIDIA API key configured. System will use fast offline rule-based fallback.")
        else:
            logger.info(f"[NvidiaNimClient] Initialized with primary model '{self.model}' and {len(self.candidate_models)-1} fallbacks.")

    def _get_headers(self):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # ------------------------------------------------------------------
    def _query_single_model(self, model: str, prompt: str, system: str = "", timeout: int = 30, retries: int = 2) -> tuple[bool, str]:
        """
        Execute request against a specific model.
        Returns (success: bool, content_or_error: str).
        """
        if not self.api_key:
            return False, "HTTP_401: No API key provided"

        url = f"{self.base_url}/chat/completions"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.2,
            "top_p": 0.7,
            "max_tokens": 1024,
            "stream": False,
        }

        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    headers=self._get_headers(),
                    json=payload,
                    timeout=timeout,
                )

                if response.status_code == 429:
                    wait = min(2 ** attempt * 1.5, 8)
                    logger.warning(
                        f"[NvidiaNimClient] Model '{model}' rate limited (429). "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(wait)
                    continue

                if response.status_code == 401:
                    return False, "HTTP_401: Unauthorized (Invalid or missing NVIDIA_API_KEY)"

                if response.status_code >= 400:
                    err_text = response.text[:120].strip()
                    return False, f"HTTP_{response.status_code}: {err_text}"

                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    return True, result["choices"][0]["message"]["content"].strip()
                return False, "EMPTY_CHOICES"

            except requests.exceptions.Timeout:
                return False, "TIMEOUT"
            except requests.exceptions.ConnectionError:
                return False, "CONNECTION_ERROR"
            except Exception as exc:
                return False, f"ERROR: {exc}"

        return False, "RATE_LIMIT_EXHAUSTED"

    # ------------------------------------------------------------------
    def query(self, prompt: str, system: str = "", timeout: int = 30) -> str:
        """
        Send a prompt to the NVIDIA NIM with automatic model failover.
        Tries primary model, then sequentially tries fallback models if errors occur.
        """
        if not self.api_key:
            return "NIM_NO_API_KEY"

        last_error = ""

        for idx, current_model in enumerate(self.candidate_models):
            success, result = self._query_single_model(
                model=current_model,
                prompt=prompt,
                system=system,
                timeout=timeout,
                retries=2,
            )

            if success and result:
                if idx > 0:
                    logger.info(f"[NvidiaNimClient] Model failover: successfully used fallback '{current_model}' (primary was '{self.model}')")
                return result

            last_error = result

            # If 401 unauthorized, it's an account key issue, so do not repeatedly loop through all models
            if "HTTP_401" in result:
                logger.warning(f"[NvidiaNimClient] {result}. Falling back to rule-based analysis.")
                return "NIM_AUTH_ERROR"

            if idx < len(self.candidate_models) - 1:
                next_model = self.candidate_models[idx + 1]
                logger.warning(
                    f"[NvidiaNimClient] Model '{current_model}' unavailable ({result}). "
                    f"Switching to fallback '{next_model}'..."
                )

        logger.error(f"[NvidiaNimClient] All models failed. Last error: {last_error}")
        return f"NIM_ALL_MODELS_FAILED:{last_error}"

    # ------------------------------------------------------------------
    def query_json(self, prompt: str, system: str = "", timeout: int = 30) -> dict:
        """
        Like query() but parses the response as JSON with robust markdown stripping
        and relaxed parsing (handling unescaped newlines and control characters).
        """
        import re

        raw = self.query(prompt, system=system, timeout=timeout)

        if raw.startswith("NIM_"):
            return {"error": raw}

        clean = raw.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            inner = parts[1] if len(parts) > 1 else ""
            if inner.startswith("json"):
                inner = inner[4:]
            clean = inner.strip()

        start_idx = clean.find('{')
        end_idx = clean.rfind('}')
        if start_idx != -1 and end_idx != -1:
            clean = clean[start_idx:end_idx+1]

        # Tier 1: Relaxed JSON decoding (handles raw newlines/tabs inside strings)
        try:
            return json.loads(clean, strict=False)
        except Exception:
            pass

        # Tier 2: Sanitize trailing commas and invalid ASCII control chars
        try:
            sanitized = re.sub(r',\s*([\]}])', r'\1', clean)
            sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', sanitized)
            return json.loads(sanitized, strict=False)
        except Exception:
            pass

        # Tier 3: Replace unescaped literal line breaks inside strings
        try:
            sanitized = re.sub(r'(?<!\\)\n', r'\\n', clean)
            return json.loads(sanitized, strict=False)
        except json.JSONDecodeError as exc:
            logger.warning(f"[NvidiaNimClient] JSON parse error on response: {exc}")
            return {"error": f"JSON parse failed: {exc}", "raw": raw}

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Quick health-check testing primary or fallback model."""
        if not self.api_key:
            return False
        for m in self.candidate_models:
            try:
                success, _ = self._query_single_model(
                    model=m,
                    prompt="ping",
                    timeout=8,
                    retries=1,
                )
                if success:
                    return True
            except Exception:
                continue
        return False
