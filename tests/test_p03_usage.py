"""PATCH 3 unit tests: one usage line per API request (mocked provider), and the run manifest."""
import json

import httpx
import openai
import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from utils import llm_usage
from utils.llm_usage import USAGE_FIELDS, LoggedChatOpenAI, UsageLog, activate, usage_scope
from utils.run_manifest import RunManifest, config_hash, derive_seed, git_info

FAKE_KEY = "sk-" + "test" + "x" * 40


def _result(with_usage=True):
    kw = {"response_metadata": {"model_name": "gpt-5-mini-2025-08-07"}}
    if with_usage:
        kw["usage_metadata"] = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                                "input_token_details": {"cache_read": 3}}
    return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok", **kw))])


def _status_error(cls, code):
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    return cls(f"{code}", response=httpx.Response(code, request=req), body=None)


class FakeProvider:
    """Stands in for the real API: each call to ChatOpenAI._generate is one request."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    # Installed as a class attribute (not a function), so it is called without `self`.
    def __call__(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        out = self.outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


@pytest.fixture
def log(tmp_path, monkeypatch):
    monkeypatch.setattr(llm_usage.time, "sleep", lambda s: None)
    return activate(UsageLog(tmp_path / "usage_log.jsonl", "run123", "proj::f()"))


def _provider(monkeypatch, outcomes):
    fake = FakeProvider(outcomes)
    monkeypatch.setattr(ChatOpenAI, "_generate", fake)
    return fake


def _lines(log):
    return [json.loads(x) for x in log.path.read_text().splitlines()] if log.path.exists() else []


def _llm(**kw):
    return LoggedChatOpenAI(api_key=FAKE_KEY, model="gpt-5-mini", **kw)


def test_success_logs_exactly_one_line_with_exact_fields(log, monkeypatch):
    fake = _provider(monkeypatch, [_result()])
    with usage_scope(call_type="mutation", generation=3):
        _llm().invoke("hi")
    lines = _lines(log)
    assert fake.calls == len(lines) == 1
    rec = lines[0]
    assert tuple(rec.keys()) == USAGE_FIELDS
    assert (rec["prompt_tokens"], rec["cached_prompt_tokens"], rec["completion_tokens"]) == (10, 3, 5)
    assert (rec["usage_source"], rec["outcome"], rec["retry_index"]) == ("provider", "ok", 0)
    assert (rec["run_id"], rec["target_id"], rec["generation"], rec["call_type"]) == ("run123", "proj::f()", 3, "mutation")
    assert rec["model"] == "gpt-5-mini" and isinstance(rec["latency_ms"], int)
    assert ("gpt-5-mini", rec["temperature"], "gpt-5-mini-2025-08-07") in log.observed_params


def test_retries_and_failures_each_logged(log, monkeypatch):
    fake = _provider(monkeypatch, [_status_error(openai.RateLimitError, 429),
                                   _status_error(openai.InternalServerError, 500), _result()])
    _llm(usage_max_retries=2).invoke("hi")
    lines = _lines(log)
    assert fake.calls == len(lines) == 3
    assert [r["retry_index"] for r in lines] == [0, 1, 2]
    assert [r["outcome"] for r in lines] == ["error:RateLimitError", "error:InternalServerError", "ok"]
    assert all(r["prompt_tokens"] is None and r["usage_source"] == "missing" for r in lines[:2])


def test_retries_exhausted_raises_and_logs_every_attempt(log, monkeypatch):
    fake = _provider(monkeypatch, [_status_error(openai.RateLimitError, 429)] * 3)
    with pytest.raises(openai.RateLimitError):
        _llm(usage_max_retries=2).invoke("hi")
    assert fake.calls == len(_lines(log)) == 3


def test_non_retryable_error_logged_once(log, monkeypatch):
    fake = _provider(monkeypatch, [_status_error(openai.BadRequestError, 400)])
    with pytest.raises(openai.BadRequestError):
        _llm().invoke("hi")
    assert fake.calls == len(_lines(log)) == 1
    assert _lines(log)[0]["outcome"] == "error:BadRequestError"


def test_response_model_read_from_llm_output(log, monkeypatch):
    res = ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))],
                     llm_output={"model_name": "gpt-5-mini-2025-08-07"})
    _provider(monkeypatch, [res])
    _llm().invoke("hi")
    assert {r for _, _, r in log.observed_params} == {"gpt-5-mini-2025-08-07"}


def test_missing_usage_is_null_not_zero(log, monkeypatch):
    _provider(monkeypatch, [_result(with_usage=False)])
    _llm().invoke("hi")
    rec = _lines(log)[0]
    assert rec["usage_source"] == "missing"
    assert rec["prompt_tokens"] is None and rec["cached_prompt_tokens"] is None and rec["completion_tokens"] is None


def test_bind_tools_stream_and_fixed_call_type_all_logged(log, monkeypatch):
    @tool
    def lookup(symbol: str) -> str:
        """Look up a symbol."""
        return symbol

    fake = _provider(monkeypatch, [_result(), _result(), _result()])
    llm = _llm()
    llm.bind_tools([lookup]).invoke("use the tool")
    list(llm.stream("streamed"))                       # disable_streaming -> one non-streaming request
    _llm(usage_call_type="code_extract").invoke("extract")
    lines = _lines(log)
    assert fake.calls == len(lines) == 3
    assert lines[2]["call_type"] == "code_extract"


def test_sdk_retries_disabled():
    assert _llm().max_retries == 0


def test_no_active_log_refuses_the_call(monkeypatch):
    monkeypatch.setattr(llm_usage, "_ACTIVE", None)
    fake = _provider(monkeypatch, [_result()])
    with pytest.raises(RuntimeError, match="usage log"):
        _llm().invoke("hi")
    assert fake.calls == 0


# ---- manifest -------------------------------------------------------------

def test_manifest_phases_and_finish(tmp_path):
    m = RunManifest(tmp_path / "run_manifest.json", run_id="r1", seed={"base_seed": 7})
    assert json.loads(m.path.read_text())["status"] == "running"
    with m.phase("initial_generation"):
        pass
    m.finish("completed", llm_requests_logged=4)
    data = json.loads(m.path.read_text())
    assert data["status"] == "completed" and data["end_time"]
    assert data["phases"]["initial_generation"]["seconds"] >= 0
    assert data["llm_requests_logged"] == 4


def test_config_hash_ignores_only_run_varying_fields():
    a = {"seed": 1, "repetition_index": 0, "save_root": "/a", "temperature": 1,
         "config": {"seed": 1, "evo_generations": 10}}
    b = {"seed": 2, "repetition_index": 4, "save_root": "/b", "temperature": 1,
         "config": {"seed": 2, "evo_generations": 10}}
    c = dict(a, temperature=0.5)
    assert config_hash(a) == config_hash(b) != config_hash(c)


def test_derive_seed_is_stable_and_target_specific():
    assert derive_seed(42, "p::f") == derive_seed(42, "p::f")
    assert derive_seed(42, "p::f") != derive_seed(42, "p::g") != derive_seed(43, "p::f")


def test_git_info_outside_repo_reports_error(tmp_path):
    info = git_info(tmp_path)
    assert info["commit"] is None and "error" in info
