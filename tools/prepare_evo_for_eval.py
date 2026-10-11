"""
prepare_evo_for_eval.py
-----------------------
Converts EvoISSTAFuzzer output to a success_functions_1.json format
that agent.eval can process.

Handles:
  - both .c and .cpp best harness files
  - empty or missing summary.json  (falls back to function.txt in run dirs)
  - run directories named run1_xxx  (not bare run1/)

Usage:
    python tools/prepare_evo_for_eval.py \
        --evo_save_root outputs/evo_gpac \
        --out_dir       outputs/evo_eval_ready

Then run eval:
    python -m agent.eval \
        --benchcfg_path cfg/evo/evo_eval.yaml \
        --output_path   outputs/evo_eval_ready \
        --n_run 1

Then get results:
    python -c "
    from agent_tools.results_analysis import get_evaluation_results
    from pathlib import Path
    get_evaluation_results(Path('outputs/evo_eval_ready'))
    "
"""

import argparse
import json
import shutil
from pathlib import Path


def _load_json_safe(path: Path):
    """Return parsed JSON or None if file missing/empty/invalid."""
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return None
        return json.loads(text)
    except Exception:
        return None


def find_best_harness(func_dir: Path):
    """
    Given: outputs/evo_<exp>/<project>/<func>/
    Returns: (best_code_path, fuzzer_name, fuzzer_path, function_signature) or None
    """
    final_dir = func_dir / "evolution" / "final"
    if not final_dir.exists():
        return None

    # Accept both .c and .cpp
    best_files = sorted(final_dir.glob("best_*.c")) + sorted(final_dir.glob("best_*.cpp"))
    if not best_files:
        return None
    best_code = best_files[0]   # best_01_... is the highest-ranked

    # Get function signature: try summary.json first, then run dirs' function.txt
    function_signature = None
    summary = _load_json_safe(final_dir / "summary.json")
    if summary:
        function_signature = summary.get("function")

    if not function_signature:
        for run_dir in sorted(func_dir.glob("run[0-9]*_*")):
            ft = run_dir / "function.txt"
            if ft.exists():
                function_signature = ft.read_text(encoding="utf-8").strip()
                break

    if not function_signature:
        function_signature = func_dir.name   # last resort: use dir name

    # Get fuzzer_info: search all run{N}_xxx dirs (highest N first = best run)
    fuzzer_name, fuzzer_path = None, None
    run_dirs = sorted(func_dir.glob("run[0-9]*_*"),
                      key=lambda p: int(p.name.split("_")[0][3:]),
                      reverse=True)
    for run_dir in run_dirs:
        fi = run_dir / "fuzzer_info.json"
        if fi.exists():
            info = _load_json_safe(fi)
            if info:
                fuzzer_name = info.get("fuzzer_name")
                fuzzer_path = info.get("fuzzer_path")
                break

    return best_code, fuzzer_name, fuzzer_path, function_signature


def prepare(evo_save_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    success_functions = {}

    for project_dir in sorted(evo_save_root.iterdir()):
        if not project_dir.is_dir():
            continue
        project_name = project_dir.name

        for func_dir in sorted(project_dir.iterdir()):
            if not func_dir.is_dir():
                continue
            if func_dir.name == "evolution":
                continue

            result = find_best_harness(func_dir)
            if result is None:
                print(f"[SKIP] {project_name}/{func_dir.name}: no final harness found")
                continue

            best_code, fuzzer_name, fuzzer_path, function_signature = result

            # Build flat work_dir: out_dir/project/func_dir_name/run_eval/
            work_dir = out_dir / project_name / func_dir.name / "run_eval"
            work_dir.mkdir(parents=True, exist_ok=True)

            # Write harness.txt
            (work_dir / "harness.txt").write_text(
                best_code.read_text(encoding="utf-8"), encoding="utf-8"
            )

            # Write fuzzer_info.json
            if fuzzer_name and fuzzer_path:
                with open(work_dir / "fuzzer_info.json", "w") as f:
                    json.dump({"fuzzer_name": fuzzer_name, "fuzzer_path": fuzzer_path}, f, indent=2)
            else:
                print(f"  [WARN] no fuzzer_info found for {project_name}/{func_dir.name}")

            # Write function.txt
            (work_dir / "function.txt").write_text(function_signature, encoding="utf-8")

            # Copy evo.log as agent.log (fallback for extract_fuzzer_name)
            evo_log = func_dir / "evolution" / "evo.log"
            if evo_log.exists():
                shutil.copy(evo_log, work_dir / "agent.log")

            # Read generation stats for reporting
            stats_file = func_dir / "evolution" / "generation_stats.json"
            stats = _load_json_safe(stats_file) or []
            gen0_cov  = stats[0]["archive_best_cov"]  if stats else "?"
            final_cov = stats[-1]["archive_best_cov"] if stats else "?"
            if gen0_cov and final_cov and gen0_cov != "?" and gen0_cov > 0:
                rel_improvement = round((final_cov - gen0_cov) / gen0_cov * 100, 1)
            else:
                rel_improvement = "?"

            key = f"{project_name}+{function_signature}"
            success_functions[key] = {
                "project":  project_name,
                "work_dir": str(work_dir.resolve()),
            }
            print(f"[OK] {project_name}::{func_dir.name}")
            print(f"     harness : {best_code.name}")
            print(f"     Gen0 cov: {gen0_cov}  →  Final cov: {final_cov}  "
                  f"(relative improvement: {rel_improvement}%)")

    # Merge with existing success_functions_1.json (so multiple evo_save_roots
    # can be accumulated by running this script multiple times)
    out_json = out_dir / "success_functions_1.json"
    existing = {}
    if out_json.exists():
        try:
            text = out_json.read_text(encoding="utf-8").strip()
            if text:
                existing = json.loads(text)
        except Exception:
            pass
    existing.update(success_functions)

    with open(out_json, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"\nWrote {len(success_functions)} new entries "
          f"(total {len(existing)}) → {out_json}")
    return out_json


def main():
    ap = argparse.ArgumentParser(description="Prepare evo results for agent.eval")
    ap.add_argument("--evo_save_root", required=True,
                    help="EvoISSTAFuzzer save_root (e.g. outputs/evo_gpac)")
    ap.add_argument("--out_dir", required=True,
                    help="Output directory for eval-ready structure")
    args = ap.parse_args()

    evo_root = Path(args.evo_save_root)
    out_dir  = Path(args.out_dir)

    if not evo_root.exists():
        raise FileNotFoundError(f"evo_save_root not found: {evo_root}")

    prepare(evo_root, out_dir)


if __name__ == "__main__":
    main()