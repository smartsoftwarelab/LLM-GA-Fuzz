"""PATCH 3 run checker: is one target run fully recorded?

Usage: python scripts/p03_check_run.py <target_dir> [--http-audit FILE]
<target_dir> = <save_root>/<project>/<function>/ (holds run_manifest.json, usage_log.jsonl, evolution/)
--http-audit: LLMGA_HTTP_AUDIT file of a single-process run, to compare request counts.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.llm_usage import USAGE_FIELDS  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("target_dir")
ap.add_argument("--http-audit", default=None)
args = ap.parse_args()
d = Path(args.target_dir)
checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, bool(ok), detail))


m = json.loads((d / "run_manifest.json").read_text())
check("manifest status completed", m.get("status") == "completed", m.get("status"))
check("code commit recorded", bool(m["code"].get("commit")), f"{m['code'].get('commit')} dirty={m['code'].get('dirty')}")
check("oss-fuzz commit recorded", bool(m["oss_fuzz"].get("commit")), str(m["oss_fuzz"].get("commit")))
images = {**m.get("docker_images_start", {}), **{f"{k} (end)": v for k, v in m.get("docker_images_end", {}).items()}}
check("base image ids recorded (end of run)", all(v.get("id") for k, v in images.items() if k.endswith("(end)")),
      "; ".join(f"{k}: {v.get('id') or v.get('error')}" for k, v in images.items()))
check("seed recorded", m["seed"].get("base_seed") is not None and m["seed"].get("target_seed") is not None,
      json.dumps(m["seed"]))
check("config + config_hash recorded", bool(m.get("config")) and len(m.get("config_hash", "")) == 64, m.get("config_hash"))
phases = m.get("phases", {})
check("phase wall-clock recorded", all(phases.get(p, {}).get("seconds") is not None
                                       for p in ("initial_generation", "initial_evaluation", "evolution")),
      ", ".join(f"{k}={v.get('seconds')}s" for k, v in phases.items()))
attempts = m.get("initial_attempts", [])
check("one record per initial attempt", len(attempts) == m["evolution"]["evo_population_size"],
      ", ".join(f"{a['index']}:{a['status']}" for a in attempts))

lines = [json.loads(x) for x in (d / "usage_log.jsonl").read_text().splitlines()]
check("usage lines have exactly the 14 fields", all(tuple(r) == USAGE_FIELDS for r in lines), f"{len(lines)} lines")
check("usage lines belong to this run", all(r["run_id"] == m["run_id"] for r in lines))
check("manifest count == usage lines", m.get("llm_requests_logged") == len(lines),
      f"{m.get('llm_requests_logged')} vs {len(lines)}")
if args.http_audit:
    posts = [x for x in Path(args.http_audit).read_text().splitlines() if "HTTP Request: POST" in x]
    check("usage lines == HTTP POST requests (audit)", len(posts) == len(lines), f"{len(lines)} vs {len(posts)}")
ok = [r for r in lines if r["outcome"] == "ok"]
check("successful requests carry provider usage", all(r["usage_source"] == "provider" for r in ok),
      f"missing={sum(r['usage_source'] == 'missing' for r in ok)}")

gen0 = sorted((d / "evolution" / "gen_000").glob("*.json"))
check("generation-0 genomes persisted with fitness status", bool(gen0) and all(
    "status" in json.loads(p.read_text())["fitness"] for p in gen0), f"{len(gen0)} genome files")

per_type: dict = defaultdict(lambda: [0, 0, 0, 0])
for r in lines:
    t = per_type[(r["generation"], r["call_type"])]
    t[0] += 1
    t[1] += r["prompt_tokens"] or 0
    t[2] += r["cached_prompt_tokens"] or 0
    t[3] += r["completion_tokens"] or 0

for name, passed, detail in checks:
    print(f"{'PASS' if passed else 'FAIL'}  {name}  [{detail}]")
print("\nrequests / prompt / cached / completion tokens by (generation, call_type) (provider-reported only):")
for key, (n, p, c, o) in sorted(per_type.items(), key=lambda kv: str(kv[0])):
    print(f"  {key}: {n} / {p} / {c} / {o}")
print("OVERALL:", "PASS" if all(p for _, p, _ in checks) else "FAIL")
