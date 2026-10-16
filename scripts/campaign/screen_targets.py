"""Step 2: walk the seeded order and keep the first targets whose OSS-Fuzz build succeeds within
the time cap (this 4-core / 3 GB server allows ~2 h per run). Every rejection is recorded.

Builds the original OSS-Fuzz project (address sanitizer, no harness change), pulls nothing,
and removes the project image afterwards to save disk.
Usage: python scripts/campaign/screen_targets.py --cap 120 [--ordered campaign/targets_ordered.json]
"""
import argparse
import json
import subprocess as sp
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--ordered", default="campaign/targets_ordered.json")
ap.add_argument("--oss-fuzz", default="/home/ubuntu/fuzzing_workspace/oss-fuzz")
ap.add_argument("--cap", type=int, default=120, help="max seconds for build_fuzzers")
ap.add_argument("--out", default="campaign/targets_selected.json")
ap.add_argument("--log", default="campaign/screening.jsonl")
args = ap.parse_args()

plan = json.loads(Path(args.ordered).read_text())
helper = Path(args.oss_fuzz) / "infra" / "helper.py"
log = Path(args.log)
done = {json.loads(x)["project"]: json.loads(x) for x in log.read_text().splitlines()} if log.exists() else {}


def run(cmd, timeout):
    t0 = time.monotonic()
    try:
        p = sp.run(cmd, stdin=sp.DEVNULL, stdout=sp.PIPE, stderr=sp.STDOUT, text=True, timeout=timeout)
        return p.returncode, time.monotonic() - t0, p.stdout[-2000:]
    except sp.TimeoutExpired:
        return "timeout", time.monotonic() - t0, ""


selected = []
for lang, quota in plan["quota"].items():
    accepted = 0
    for t in plan["order"][lang]:
        if accepted >= quota:
            break
        rec = done.get(t["project"])
        if rec is None:
            proj = t["project"]
            rc_i, img_s, _ = run(["python3", str(helper), "build_image", proj, "--no-pull"], 1800)
            rc_b, fz_s, tail = (None, None, "")
            if rc_i == 0:
                rc_b, fz_s, tail = run(["python3", str(helper), "build_fuzzers", proj], args.cap + 60)
            fuzzer = Path(args.oss_fuzz) / "build" / "out" / proj / (t["target_name"] or "")
            if rc_i != 0:
                result = "image_failed"
            elif rc_b == "timeout" or (fz_s or 0) > args.cap:
                result = "too_slow"
            elif rc_b != 0:
                result = "build_failed"
            elif not (t["target_name"] and fuzzer.exists()):
                result = "fuzzer_missing"
            else:
                result = "ok"
            rec = {"timestamp": datetime.now(timezone.utc).isoformat(), "project": proj, "language": lang,
                   "build_image_s": round(img_s, 1), "build_fuzzers_s": None if fz_s is None else round(fz_s, 1),
                   "cap_s": args.cap, "result": result, "tail": tail[-500:] if result != "ok" else ""}
            with log.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            sp.run(["docker", "rmi", "-f", f"gcr.io/oss-fuzz/{proj}"], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        print(f"{lang:4s} {t['project']:28s} {rec['result']:15s} build_fuzzers={rec['build_fuzzers_s']}s")
        if rec["result"] == "ok":
            accepted += 1
            selected.append({**t, "screen": rec})
    if accepted < quota:
        print(f"WARNING: only {accepted}/{quota} {lang} targets passed the screen")

Path(args.out).write_text(json.dumps({"cap_s": args.cap, "seed": plan["seed"], "quota": plan["quota"],
                                      "selected": selected}, indent=2))
print(f"selected {len(selected)} targets -> {args.out}")
