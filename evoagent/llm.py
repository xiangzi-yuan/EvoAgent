"""Small OpenAI-compatible JSON client with auditable usage accounting."""
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .telemetry import ExecutionLedger


class JsonChatClient:
    def __init__(
        self, base_url: str, api_key: str, model: str,
        provider: str = "openai-compatible", timeout: int = 60,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})

    def complete_json(
        self, role: str, system: str, user: str,
        ledger: Optional[ExecutionLedger] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        # DeepSeek v4 can spend the entire completion allowance on hidden
        # reasoning and return an empty content field. EvoAgent's role
        # protocol requires a JSON object in content, so disable thinking for
        # this structured transport.
        if self.provider == "deepseek":
            payload["thinking"] = {"type": "disabled"}
        elif "api.siliconflow.cn" in self.base_url.lower():
            payload["enable_thinking"] = False
        if max_tokens:
            payload["max_tokens"] = int(max_tokens)
        headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(self.extra_headers)
        for attempt in range(2):
            payload["messages"] = messages
            request = urllib.request.Request(
                self.base_url + "/chat/completions",
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers=headers, method="POST",
            )
            started = time.monotonic()
            body: Dict[str, Any] = {}
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                content = str(body["choices"][0]["message"]["content"])
            except urllib.error.HTTPError as exc:
                detail = exc.read(1000).decode("utf-8", errors="replace")
                message = "%s API returned HTTP %d: %s" % (
                    self.provider, exc.code, detail,
                )
            except (urllib.error.URLError, socket.timeout, ValueError, KeyError,
                    IndexError, TypeError, json.JSONDecodeError) as exc:
                message = "%s JSON request failed: %s" % (self.provider, exc)
            else:
                candidate = content.strip()
                if candidate.startswith("```json") and candidate.endswith("```"):
                    candidate = candidate[7:-3].strip()
                elif candidate.startswith("```") and candidate.endswith("```"):
                    candidate = candidate[3:-3].strip()
                try:
                    result = json.loads(candidate)
                    if not isinstance(result, dict):
                        raise ValueError("model JSON root is not an object")
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    message = "%s JSON request failed: %s" % (self.provider, exc)
                    if ledger:
                        ledger.record_model(
                            role, self.provider, self.model, body.get("usage") or {},
                            int((time.monotonic() - started) * 1000), False,
                            message + " (structured-output retry %d/1)" % (attempt + 1),
                        )
                    if attempt == 0:
                        messages = [
                            *messages,
                            {"role": "assistant", "content": content[:16000]},
                            {
                                "role": "user",
                                "content": (
                                    "The previous response was not valid JSON. Correct only "
                                    "its JSON syntax and return one strict JSON object with no "
                                    "Markdown fence or explanatory text."
                                ),
                            },
                        ]
                        continue
                    raise RuntimeError(message)
                if ledger:
                    ledger.record_model(
                        role, self.provider, self.model, body.get("usage") or {},
                        int((time.monotonic() - started) * 1000), True,
                    )
                return result
            if ledger:
                ledger.record_model(
                    role, self.provider, self.model, body.get("usage") or {},
                    int((time.monotonic() - started) * 1000), False, message,
                )
            raise RuntimeError(message)
        raise RuntimeError("%s JSON request failed" % self.provider)
