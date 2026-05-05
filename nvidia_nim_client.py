"""
nvidia_nim_client.py — Shared LLM interface for all three agents.
Talks to NVIDIA NIM API (internet required for hosted, or local NIM instance).
"""

import json
import logging
import requests

logger = logging.getLogger(__name__)


class NvidiaNimClient:
    """
    Wraps the NVIDIA NIM REST API (OpenAI-compatible).
    All agents share one instance of this class.

    For hosted NIM, use: https://integrate.api.nvidia.com/v1
    For local NIM, use: http://localhost:8000/v1
    """

    def __init__(
        self, 
        base_url: str = "https://integrate.api.nvidia.com/v1", 
        model: str = "meta/llama-3.1-8b-instruct",
        api_key: str = None
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        logger.info(f"[NvidiaNimClient] Using model '{model}' at {base_url}")

    def _get_headers(self):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # ------------------------------------------------------------------
    def query(self, prompt: str, system: str = "", timeout: int = 120) -> str:
        """
        Send a prompt to the NVIDIA NIM and return its text response.
        """
        url = f"{self.base_url}/chat/completions"
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "top_p": 0.7,
            "max_tokens": 1024,
            "stream": False,
        }

        try:
            response = requests.post(
                url, 
                headers=self._get_headers(), 
                json=payload, 
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()
            
            # OpenAI compatible response structure
            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"].strip()
            return ""

        except requests.exceptions.ConnectionError:
            logger.error(f"[NvidiaNimClient] Cannot reach NIM at {self.base_url}")
            return "NIM_UNAVAILABLE"

        except requests.exceptions.HTTPError as exc:
            logger.error(f"[NvidiaNimClient] HTTP Error: {exc.response.text}")
            return f"NIM_HTTP_ERROR:{exc.response.status_code}"

        except requests.exceptions.Timeout:
            logger.error(f"[NvidiaNimClient] Request timed out after {timeout}s")
            return "NIM_TIMEOUT"

        except Exception as exc:
            logger.error(f"[NvidiaNimClient] Unexpected error: {exc}")
            return f"NIM_ERROR:{exc}"

    # ------------------------------------------------------------------
    def query_json(self, prompt: str, system: str = "", timeout: int = 120) -> dict:
        """
        Like query() but parses the response as JSON.
        Handles markdown code-fences.
        """
        raw = self.query(prompt, system=system, timeout=timeout)

        if raw.startswith("NIM_"):
            return {"error": raw}

        # Strip markdown fences like ```json … ```
        clean = raw.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            # parts[1] contains the language tag + content
            inner = parts[1] if len(parts) > 1 else ""
            if inner.startswith("json"):
                inner = inner[4:]
            clean = inner.strip()
        
        # Sometimes models put extra text after the closing fence or have multiple fences
        # Find the first { and last }
        start_idx = clean.find('{')
        end_idx = clean.rfind('}')
        if start_idx != -1 and end_idx != -1:
            clean = clean[start_idx:end_idx+1]

        try:
            return json.loads(clean)
        except json.JSONDecodeError as exc:
            logger.warning(f"[NvidiaNimClient] JSON parse failed: {exc}")
            logger.debug(f"[NvidiaNimClient] Raw response was:\n{raw[:500]}")
            return {"error": f"JSON parse failed: {exc}", "raw": raw}

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Quick health-check."""
        try:
            # We can try to list models or just do a small health check
            # For NIM, we can hit /v1/models (if supported) or just a minimal completion
            r = requests.get(f"{self.base_url}/models", headers=self._get_headers(), timeout=5)
            return r.status_code == 200
        except Exception:
            return False
