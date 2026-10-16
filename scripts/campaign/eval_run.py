"""Step 4 (per run): llvm-cov branch coverage of the best generation-0 harness (non-evolutionary
baseline) and the best final harness, each fuzzed for the same time with the same seed.

Usage: python scripts/campaign/eval_run.py <target_dir> --cfg <run config.yaml> [--minutes 5]
Writes <target_dir>/eval/eval_results.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agent.eval import process_single_result  # noqa: E402
from bench_cfg import BenchConfig  # noqa: E402
from utils.campaign import pick_final_best, pick_gen0_best  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("target_dir")
ap.add_argument("--cfg", required=True)
ap.add_argument("--minutes", type=int, default=5)
args = ap.parse_args()

target_dir = Path(args.target_dir).resolve()
manifest = json.loads((target_dir / "run_manifest.json").read_text())
fuzzer_info = next(iter(sorted(target_dir.glob("run[0-9]*_*/fuzzer_info.json"))), None)
if manifest.get("status") != "completed" or fuzzer_info is None:
    sys.exit(f"cannot evaluate {target_dir}: status={manifest.get('status')} fuzzer_info={fuzzer_info}")

results = {}
first_by_genome = {}
for label, genome in (("gen0_best", pick_gen0_best(target_dir)), ("final_best", pick_final_best(target_dir))):
    if genome is None:
        results[label] = {"genome_id": None, "coverage": {"status": "TOOL_FAILED", "error_message": "no genome"}}
        continue
    if genome["genome_id"] in first_by_genome:          # evolution kept the gen-0 harness: same code
        results[label] = {**results[first_by_genome[genome["genome_id"]]], "reused_from": first_by_genome[genome["genome_id"]]}
        continue
    work = target_dir / "eval" / label / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / "harness.txt").write_text(genome["code"], encoding="utf-8")
    (work / "function.txt").write_text(manifest["function"], encoding="utf-8")
    (work / "fuzzer_info.json").write_text(fuzzer_info.read_text())
    cfg = BenchConfig(args.cfg)
    cfg.save_root = target_dir / "eval" / label
    cfg.run_time = args.minutes
    _, _, record = process_single_result((manifest["project"], manifest["function"], work, cfg))
    results[label] = {"genome_id": genome["genome_id"], "generation": genome["generation"],
                      "fitness_total": genome["fitness"]["total"], **record}
    first_by_genome[genome["genome_id"]] = label

out = target_dir / "eval" / "eval_results.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({"fuzz_minutes": args.minutes, "results": results}, indent=2))
for label, r in results.items():
    c = r.get("coverage", {})
    print(f"{label}: genome={r.get('genome_id')} status={c.get('status')} {c.get('metric')}={c.get('covered')}/{c.get('total')}")
