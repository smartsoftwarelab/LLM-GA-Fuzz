#!/usr/bin/env python3
"""
Create success_functions_1.json from existing output directories so that
agent/eval.py can re-evaluate them and produce edge coverage percentages.

For each function, picks the BEST available run (highest run number that has
fuzzer_info.json + harness.txt + function.txt). Skips evolution/ subdirs.

Usage:
    # single project dir
    python tools/make_eval_json.py --output_path outputs/evo_cjson_/cjson

    # root dir with multiple projects
    python tools/make_eval_json.py --output_path outputs/evo_cjson_

    # then run evaluation:
    python -m agent.eval \
        --output_path outputs/evo_cjson_/cjson \
        --benchcfg_path cfg/evo/evo_cjson.yaml \
        --n_run 1
"""

import argparse
import json
from pathlib import Path


def is_run_dir(p: Path) -> bool:
    """True for run1_xxx, run2_xxx … but NOT evolution/ dirs."""
    return (p.is_dir()
            and p.name.startswith("run")
            and "_" in p.name
            and p.name.split("_")[0][3:].isdigit())


def best_run(function_path: Path) -> tuple[int, Path] | None:
    """
    Return (run_number, run_dir) for the highest-numbered run that has
    the three required files.  Returns None if no valid run found.
    """
    candidates: list[tuple[int, Path]] = []
    for run_dir in function_path.iterdir():
        if not is_run_dir(run_dir):
            continue
        if not (run_dir / "fuzzer_info.json").exists():
            continue
        if not (run_dir / "harness.txt").exists():
            continue
        if not (run_dir / "function.txt").exists():
            continue
        run_num = int(run_dir.name.split("_")[0][3:])
        candidates.append((run_num, run_dir))

    if not candidates:
        return None
    return max(candidates, key=lambda x: x[0])


def collect_from_project(project_path: Path) -> list[tuple[str, int, Path]]:
    """Returns list of (project_name, run_num, run_dir)."""
    results = []
    project_name = project_path.name
    for function_path in sorted(project_path.iterdir()):
        if not function_path.is_dir():
            continue
        if function_path.name == "evolution":
            continue
        hit = best_run(function_path)
        if hit is None:
            print(f"  [SKIP] no valid run: {function_path}")
            continue
        run_num, run_dir = hit
        results.append((project_name, run_num, run_dir))
    return results


def make_success_json(output_path: Path) -> Path:
    """
    Auto-detect layout and build success_functions_1.json.
    Layout detection:
      - if children contain run* dirs  → output_path is a function dir
      - if grandchildren contain run*  → output_path is a project dir
      - otherwise                      → output_path is a root dir
    """
    success_json: dict = {}

    children = [p for p in output_path.iterdir() if p.is_dir()]

    all_hits: list[tuple[str, int, Path]] = []

    if any(is_run_dir(c) for c in children):
        # output_path IS the function directory
        project_name = output_path.parent.name
        hit = best_run(output_path)
        if hit:
            all_hits.append((project_name, hit[0], hit[1]))

    elif any(
        is_run_dir(gc)
        for c in children if c.is_dir() and c.name != "evolution"
        for gc in c.iterdir()
    ):
        # output_path is a project dir
        all_hits = collect_from_project(output_path)

    else:
        # output_path is root (multiple projects)
        for project_path in sorted(children):
            if not project_path.is_dir():
                continue
            all_hits.extend(collect_from_project(project_path))

    for project_name, run_num, run_dir in all_hits:
        func_sig = (run_dir / "function.txt").read_text().strip()
        key = f"{project_name}+{func_sig}"
        success_json[key] = {
            "project": project_name,
            "work_dir": str(run_dir.resolve()),
        }
        print(f"  [OK] run{run_num}  {project_name} :: {func_sig}")

    out_file = output_path / "success_functions_1.json"
    with open(out_file, "w") as f:
        json.dump(success_json, f, indent=4)

    print(f"\nWrote {len(success_json)} entries → {out_file}")
    return out_file


def main():
    parser = argparse.ArgumentParser(
        description="Build success_functions_1.json for eval.py from existing outputs"
    )
    parser.add_argument(
        "--output_path", required=True,
        help="Project-level dir (outputs/evo_cjson_/cjson) or root dir (outputs/evo_cjson_)"
    )
    args = parser.parse_args()

    output_path = Path(args.output_path)
    if not output_path.exists():
        print(f"ERROR: path does not exist: {output_path}")
        return

    make_success_json(output_path)


if __name__ == "__main__":
    main()