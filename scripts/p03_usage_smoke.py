"""PATCH 3 real-API smoke test: usage_log.jsonl lines == HTTP requests seen by httpx.

Makes a handful of small requests (a few cents) through LoggedChatOpenAI, along the
same code paths the pipeline uses: plain invoke, bind_tools, structured output
(as in code_extract, temperature=0), and .stream().
Usage: python scripts/p03_usage_smoke.py [--model gpt-5-mini] [--out /tmp/p03_smoke]
"""
import argparse
import json
import os
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="gpt-5-mini")
ap.add_argument("--out", default="/tmp/p03_smoke")
args = ap.parse_args()
out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
audit = out / "http_audit.log"
usage = out / "usage_log.jsonl"
for f in (audit, usage):
    f.unlink(missing_ok=True)
os.environ["LLMGA_HTTP_AUDIT"] = str(audit)       # must be set before importing llm_usage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from langchain_core.tools import tool  # noqa: E402
from agent.modules.code_format import CodeAnswerStruct  # noqa: E402
from utils.llm_usage import USAGE_FIELDS, LoggedChatOpenAI, UsageLog, activate, usage_scope  # noqa: E402


@tool
def get_symbol_header(symbol: str) -> str:
    """Return the header that declares `symbol`."""
    return "#include <stdio.h>"


log = activate(UsageLog(usage, "smoke", "smoke::none"))
llm = LoggedChatOpenAI(model=args.model)                                     # as gen.py / evo_gen.py (gpt-5-mini branch)
extract = LoggedChatOpenAI(model=args.model, temperature=0, usage_call_type="code_extract")  # as gen.py llm_extract
print("sdk max_retries:", llm.root_client.max_retries)

steps = [
    ("plain", lambda: llm.invoke("Reply with the single word: ok")),
    ("bind_tools", lambda: llm.bind_tools([get_symbol_header]).invoke("Which header declares printf? Use the tool.")),
    ("structured_t0", lambda: extract.with_structured_output(CodeAnswerStruct).invoke(
        "Split this answer: Here is code:\n```c\nint main(void){return 0;}\n```\nDone.")),
    ("stream", lambda: list(llm.stream("Reply with the single word: ok"))),
]
for name, fn in steps:
    with usage_scope(call_type=name, generation=0):
        try:
            fn()
            print(f"{name}: ok")
        except Exception as exc:
            print(f"{name}: raised {type(exc).__name__}: {str(exc)[:200]}")

records = [json.loads(x) for x in usage.read_text().splitlines()]
posts = [x for x in audit.read_text().splitlines() if "HTTP Request: POST" in x] if audit.exists() else []
print("\n--- usage_log.jsonl ---")
for r in records:
    print({k: r[k] for k in ("call_type", "model", "temperature", "prompt_tokens", "cached_prompt_tokens",
                             "completion_tokens", "usage_source", "retry_index", "outcome", "latency_ms")})
print("\n--- http_audit.log (POST lines) ---")
for p in posts:
    print(p[:200])
ok = [r for r in records if r["outcome"] == "ok"]
checks = [
    ("usage lines == HTTP POST requests", len(records) == len(posts) and len(records) > 0),
    ("every line has exactly the 14 fields", all(tuple(r) == USAGE_FIELDS for r in records)),
    ("successful requests carry provider usage (non-null tokens)",
     all(r["usage_source"] == "provider" and isinstance(r["prompt_tokens"], int)
         and isinstance(r["completion_tokens"], int) for r in ok)),
    ("SDK-internal retries disabled", llm.root_client.max_retries == 0),
]
for name, passed in checks:
    print(f"{'PASS' if passed else 'FAIL'}  {name}")
print(f"usage_lines={len(records)} http_posts={len(posts)} observed_params={sorted(log.observed_params, key=str)}")
print("OVERALL:", "PASS" if all(p for _, p in checks) else "FAIL")
