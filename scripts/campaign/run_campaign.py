"""Step 3: run the campaign, one run at a time (4-core / 3 GB server).

Order is target-major (all repetitions of a target before the next target), so if time runs
out the campaign loses targets, never repetitions. Resumable: completed runs are skipped.
Create <out>/STOP to stop cleanly after the current run.

Usage: setsid nohup python scripts/campaign/run_campaign.py > outputs/campaign_launcher.log 2>&1 < /dev/null &
Keep logs under outputs/ (git-ignored) so the code tree stays clean (gate G7).
"""
import argparse
import json
import os
import shutil
import subprocess as sp
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.campaign import LANG_LABEL, find_target_dir, manifest_status, rep_seed, run_key  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--targets", default="campaign/targets_selected.json")
ap.add_argument("--template", default="cfg/campaign/campaign.yaml")
ap.add_argument("--out", default="outputs/campaign")
ap.add_argument("--reps", type=int, default=5)
ap.add_argument("--campaign-seed", type=int, default=20261016)
ap.add_argument("--eval-minutes", type=int, default=5)
ap.add_argument("--dry-run", action="store_true")
args = ap.parse_args()

out = Path(args.out).resolve()
for sub in ("configs", "logs", "audit", "timings"):
    (out / sub).mkdir(parents=True, exist_ok=True)
targets = json.loads(Path(args.targets).read_text())["selected"]
template = yaml.safe_load(Path(args.template).read_text())
progress = out / "progress.jsonl"


def log_progress(**rec):
    rec["timestamp"] = datetime.now(timezone.utc).isoformat()
    with progress.open("a") as f:
        f.write(json.dumps(rec) + "\n")


for t in targets:
    for r in range(1, args.reps + 1):
        if (out / "STOP").exists():
            print("STOP file found, exiting"); sys.exit(0)
        key = run_key(t["project"], r)
        save_root = out / f"rep{r}"
        target_dir = find_target_dir(save_root, t["project"])
        done = manifest_status(target_dir) == "completed" and (target_dir / "eval" / "eval_results.json").exists()
        if done:
            continue
        if manifest_status(target_dir) not in (None, "completed"):
            # never resume inside a failed run: its workspaces would be reused as CACHED harnesses
            dest = out / "failed" / f"{key}_{int(time.time())}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target_dir.parent), str(dest))
            for side in (out / "audit" / f"{key}.log", out / "timings" / f"{key}.jsonl"):
                if side.exists():                          # keep G3 counts per attempt
                    shutil.move(str(side), str(dest / side.name))
            log_progress(run=key, phase="moved_failed_run", to=str(dest))
            target_dir = None
        cfg = {**template, "save_root": str(save_root), "project_name": [t["project"]],
               "function_signatures": [t["signature"]], "language": LANG_LABEL[t["language"]],
               "seed": rep_seed(args.campaign_seed, r), "repetition_index": r}
        cfg_path = out / "configs" / f"{key}.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))
        env = {**os.environ, "LLMGA_HTTP_AUDIT": str(out / "audit" / f"{key}.log"),
               "LLMGA_BUILD_TIMINGS": str(out / "timings" / f"{key}.jsonl")}
        print(f"[{datetime.now():%m-%d %H:%M}] {key}: seed={cfg['seed']}", flush=True)
        if args.dry_run:
            continue
        t0 = time.time()
        if manifest_status(target_dir) != "completed":
            with (out / "logs" / f"{key}.log").open("a") as lf:
                rc = sp.run([sys.executable, "-m", "agent.run_evo_gen", str(cfg_path), "--processes", "1",
                             "--project", t["project"], "--function", t["signature"]],
                            stdout=lf, stderr=sp.STDOUT, stdin=sp.DEVNULL, env=env).returncode
            target_dir = find_target_dir(save_root, t["project"])
            log_progress(run=key, phase="evolution", rc=rc, status=manifest_status(target_dir),
                         seconds=round(time.time() - t0))
        if manifest_status(target_dir) == "completed":
            t1 = time.time()
            with (out / "logs" / f"{key}.eval.log").open("a") as lf:
                rc = sp.run([sys.executable, "scripts/campaign/eval_run.py", str(target_dir), "--cfg", str(cfg_path),
                             "--minutes", str(args.eval_minutes)], stdout=lf, stderr=sp.STDOUT,
                            stdin=sp.DEVNULL, env=env).returncode
            log_progress(run=key, phase="eval", rc=rc, seconds=round(time.time() - t1))
print("campaign finished")
