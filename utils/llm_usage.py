"""Per-request LLM usage accounting.

Every chat-model request made by the pipeline goes through LoggedChatOpenAI,
which appends exactly one JSON line per API request (successes, failures and
retries) to the active UsageLog. Token fields come only from the provider's
response; when the provider returns no usage they are null with
usage_source="missing" -- never estimated, never 0.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, Optional, Union

import openai
from langchain_core.runnables.config import run_in_executor
from langchain_openai import ChatOpenAI

USAGE_FIELDS = ("timestamp", "run_id", "target_id", "generation", "call_type", "model", "temperature",
                "prompt_tokens", "cached_prompt_tokens", "completion_tokens", "usage_source",
                "retry_index", "outcome", "latency_ms")

# Jitter for retry backoff; separate from the global `random` so the
# experiment's seeded selection stream is not consumed by retries.
_JITTER = random.Random()

# Optional independent audit: LLMGA_HTTP_AUDIT=<file> appends httpx's own
# "HTTP Request: POST ..." line for every request, to cross-check the usage log.
HTTP_AUDIT_PATH = os.environ.get("LLMGA_HTTP_AUDIT")
if HTTP_AUDIT_PATH:
    _audit = logging.FileHandler(HTTP_AUDIT_PATH)
    _audit.setFormatter(logging.Formatter("%(asctime)s %(process)d %(message)s"))
    logging.getLogger("httpx").addHandler(_audit)
    logging.getLogger("httpx").setLevel(logging.INFO)


class UsageLog:
    """Append-only usage_log.jsonl for one run (one target, one repetition)."""

    def __init__(self, path: Path, run_id: str, target_id: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.target_id = target_id
        self.call_type: Optional[str] = None
        self.generation: Optional[int] = None
        self.n_records = 0
        # (requested model, temperature sent, model reported by the provider)
        self.observed_params: set[tuple[Any, Any, Any]] = set()
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def scope(self, call_type: Optional[str] = None, generation: Optional[int] = None) -> Iterator[None]:
        prev = (self.call_type, self.generation)
        if call_type is not None:
            self.call_type = call_type
        if generation is not None:
            self.generation = generation
        try:
            yield
        finally:
            self.call_type, self.generation = prev

    def write(self, **fields: Any) -> None:
        record = {k: fields.get(k) for k in USAGE_FIELDS}
        record.update(timestamp=datetime.now(timezone.utc).isoformat(), run_id=self.run_id,
                      target_id=self.target_id)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            self.n_records += 1


_ACTIVE: Optional[UsageLog] = None


def activate(log: UsageLog) -> UsageLog:
    """Make `log` the destination of all LLM requests in this process."""
    global _ACTIVE
    _ACTIVE = log
    return log


def active_log() -> UsageLog:
    if _ACTIVE is None:
        raise RuntimeError("LLM request without an active usage log; call utils.llm_usage.activate() first")
    return _ACTIVE


def usage_scope(call_type: Optional[str] = None, generation: Optional[int] = None):
    """Label the requests made inside the `with` block (call_type / generation)."""
    return active_log().scope(call_type=call_type, generation=generation)


def _is_retryable(exc: BaseException) -> bool:
    # Same classes of failure the OpenAI SDK retries by default.
    if isinstance(exc, openai.APIConnectionError):  # includes APITimeoutError
        return True
    if isinstance(exc, openai.APIStatusError):
        return exc.status_code in (408, 409, 429) or exc.status_code >= 500
    return False


def _backoff_seconds(attempt: int, exc: BaseException) -> float:
    response = getattr(exc, "response", None)
    try:
        retry_after = float(response.headers.get("retry-after")) if response is not None else None
    except (TypeError, ValueError):
        retry_after = None
    if retry_after is not None and 0 < retry_after <= 60:
        return retry_after
    return min(0.5 * 2 ** attempt, 8.0) * (1 - 0.25 * _JITTER.random())


def _usage_fields(result: Any) -> tuple[dict[str, Optional[int]], str, Optional[str]]:
    message = result.generations[0].message if getattr(result, "generations", None) else None
    usage = getattr(message, "usage_metadata", None)
    # Provider-reported model snapshot: on the message, or (at the _generate level) in llm_output.
    response_model = ((getattr(message, "response_metadata", None) or {}).get("model_name")
                      or (getattr(result, "llm_output", None) or {}).get("model_name"))
    if not usage:
        return {"prompt_tokens": None, "cached_prompt_tokens": None, "completion_tokens": None}, "missing", response_model
    details = usage.get("input_token_details") or {}
    return ({"prompt_tokens": usage.get("input_tokens"),
             "cached_prompt_tokens": details.get("cache_read"),
             "completion_tokens": usage.get("output_tokens")}, "provider", response_model)


class LoggedChatOpenAI(ChatOpenAI):
    """ChatOpenAI that logs one usage line per API request.

    SDK-internal retries are disabled (max_retries=0) and performed here instead,
    so every attempt -- including failed ones -- is a separate, logged request.
    Streaming is disabled so all requests go through _generate.
    """

    max_retries: Optional[int] = 0
    disable_streaming: Union[bool, Literal["tool_calling"]] = True
    usage_call_type: Optional[str] = None   # fixed call_type for this model (e.g. "code_extract")
    usage_max_retries: int = 2              # retries after the first attempt (config llm_max_retries)

    def _sent_temperature(self, messages: Any, stop: Any, **kwargs: Any) -> Any:
        try:
            return self._get_request_payload(messages, stop=stop, **kwargs).get("temperature")
        except Exception:
            return self.temperature

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
        log = active_log()
        call_type = self.usage_call_type or log.call_type
        temperature = self._sent_temperature(messages, stop, **kwargs)
        attempt = 0
        while True:
            t0 = time.monotonic()
            try:
                result = super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            except Exception as exc:
                log.write(generation=log.generation, call_type=call_type, model=self.model_name,
                          temperature=temperature, prompt_tokens=None, cached_prompt_tokens=None,
                          completion_tokens=None, usage_source="missing", retry_index=attempt,
                          outcome=f"error:{type(exc).__name__}",
                          latency_ms=round((time.monotonic() - t0) * 1000))
                if attempt < self.usage_max_retries and _is_retryable(exc):
                    time.sleep(_backoff_seconds(attempt, exc))
                    attempt += 1
                    continue
                raise
            tokens, source, response_model = _usage_fields(result)
            log.write(generation=log.generation, call_type=call_type, model=self.model_name,
                      temperature=temperature, usage_source=source, retry_index=attempt, outcome="ok",
                      latency_ms=round((time.monotonic() - t0) * 1000), **tokens)
            log.observed_params.add((self.model_name, temperature, response_model))
            return result

    async def _agenerate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
        # Route async calls through the logged sync path.
        return await run_in_executor(None, self._generate, messages, stop, None, **kwargs)
