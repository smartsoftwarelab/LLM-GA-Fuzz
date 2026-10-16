"""Step 1: seeded, language-stratified order of all benchmark targets + quotas for N targets.

Commit the output before any run. Screening (screen_targets.py) walks this order.
Usage: python scripts/campaign/sample_targets.py --n 12 --seed 20261016 --out campaign/targets_ordered.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.campaign import load_benchmark, stratified_order  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--bench-dir", default="benchmark-sets/function_0")
ap.add_argument("--n", type=int, default=12)
ap.add_argument("--seed", type=int, default=20261016)
ap.add_argument("--out", default="campaign/targets_ordered.json")
args = ap.parse_args()

targets = load_benchmark(Path(args.bench_dir))
plan = stratified_order(targets, args.seed, args.n)
plan["bench_dir"] = args.bench_dir
out = Path(args.out)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(plan, indent=2))
print(f"targets: {len(targets)}  counts: {plan['counts']}  quota: {plan['quota']}  seed: {args.seed}")
for lang, items in plan["order"].items():
    print(f"  {lang}: first 6 in order -> {[t['project'] for t in items[:6]]}")
print(f"written: {out}")
