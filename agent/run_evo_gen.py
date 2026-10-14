from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import traceback
from multiprocessing import Pool
from pathlib import Path

from bench_cfg import BenchConfig
from utils.misc import extract_name, get_benchmark_functions
from utils.oss_fuzz_utils import OSSFuzzUtils
from agent.evo_gen import EvoISSTAFuzzer
from agent_tools.results_analysis import run_agent_res


# Argument parsing

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EvoISSTAFuzzer — evolutionary fuzz harness generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "config",
        help="Path to YAML configuration file",
    )
    p.add_argument(
        "--project", "-p",
        default=None,
        help="Override: target project name",
    )
    p.add_argument(
        "--function", "-f",
        default=None,
        help="Override: target function signature (use with --project)",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Skip functions whose 'evolution/final/summary.json' already exists",
    )
    p.add_argument(
        "--processes",
        type=int,
        default=None,
        help="Override: number of parallel processes (default: from config)",
    )
    return p.parse_args()


# Single-function runner (designed to be picklable for multiprocessing)

def _run_one(
    cfg: BenchConfig,
    function_signature: str,
    project_name: str,
    resume: bool,
) -> dict:
    """
    Run the evolutionary pipeline for one function.
    Returns a summary dict (written to disk by EvoISSTAFuzzer anyway).
    """
    func_name = extract_name(
        function_signature, keep_namespace=True, language=cfg.language
    ).replace("::", "_")
    evo_dir    = cfg.save_root / project_name.lower() / func_name.lower() / "evolution"
    final_file = evo_dir / "final" / "summary.json"

    # Resume check
    if resume and final_file.exists():
        print(f"[SKIP] {project_name}::{function_signature} (already done)")
        return {"skipped": True}

    print(f"\n[EvoFuzzer] Starting: {project_name}::{function_signature}")
    t0 = time.time()

    try:
        evo  = EvoISSTAFuzzer(cfg, function_signature, project_name)
        best = evo.run()

        elapsed = time.time() - t0
        summary = {
            "project":   project_name,
            "function":  function_signature,
            "elapsed_s": round(elapsed, 1),
            "n_best":    len(best),
            "best_coverage": best[0].fitness.coverage if best else None,
            "crash_found":   any(g.fitness.crash_found for g in best),
        }
        print(
            f"[EvoFuzzer] Done: {project_name}::{function_signature}  "
            f"coverage={summary['best_coverage']}  "
            f"elapsed={elapsed:.0f}s"
        )
        return summary

    except Exception as exc:
        elapsed = time.time() - t0
        print(f"[EvoFuzzer] ERROR: {project_name}::{function_signature}: {exc}")
        traceback.print_exc()
        return {
            "project":  project_name,
            "function": function_signature,
            "error":    str(exc),
            "elapsed_s": round(elapsed, 1),
        }


# Batch runner

class EvoRunner:
    """Orchestrates parallel evolutionary runs across all benchmark functions."""

    def __init__(self, cfg_path: str, processes: int | None, resume: bool):
        self.cfg      = BenchConfig(cfg_path)
        self.n_procs  = processes or self.cfg.num_processes
        self.resume   = resume

    # -----------------------------------------------------------------------

    def _already_done(self, function_signature: str, project_name: str) -> bool:
        func_name = extract_name(
            function_signature, keep_namespace=True, language=self.cfg.language
        ).replace("::", "_")
        summary_file = (
            self.cfg.save_root
            / project_name.lower()
            / func_name.lower()
            / "evolution"
            / "final"
            / "summary.json"
        )
        return summary_file.exists()

    def _collect_results(self) -> dict:
        """Walk the save_root tree and collect all summary.json files."""
        results = {}
        for summary_file in self.cfg.save_root.rglob("evolution/final/summary.json"):
            try:
                with open(summary_file, encoding="utf-8") as f:
                    data = json.load(f)
                key = f"{data.get('project')}+{data.get('function')}"
                results[key] = data
            except Exception:
                pass
        return results

    # -----------------------------------------------------------------------

    def run(self) -> None:
        os.makedirs(self.cfg.save_root, exist_ok=True)

        # Collect target functions from benchmark
        function_dicts = get_benchmark_functions(
            self.cfg.benchmark_dir,
            allowed_projects   = self.cfg.project_name if self.cfg.project_name else [],
            allowed_functions  = self.cfg.function_signatures,
            funcs_per_project  = self.cfg.funcs_per_project,
            language           = self.cfg.language,
        )

        # Build the flat task list
        tasks: list[tuple[str, str]] = []   # (project, function_signature)
        for project, functions in function_dicts.items():
            for func_sig in functions:
                if self.resume and self._already_done(func_sig, project):
                    print(f"[SKIP] {project}::{func_sig}")
                    continue
                tasks.append((project, func_sig))

        total = len(tasks)
        if total == 0:
            print("Nothing to run (all functions already done or no benchmark found).")
            return

        print(f"\n[EvoRunner] {total} function(s) to evolve "
              f"using {self.n_procs} process(es).\n")

        t_start = time.time()

        if self.n_procs == 1:
            # Serial execution (easier to debug)
            for project, func_sig in tasks:
                _run_one(self.cfg, func_sig, project, self.resume)
        else:
            with Pool(processes=self.n_procs) as pool:
                for project, func_sig in tasks:
                    pool.apply_async(
                        _run_one,
                        args=(self.cfg, func_sig, project, self.resume),
                    )
                pool.close()
                pool.join()

        # Aggregate results
        results = self._collect_results()
        results_path = self.cfg.save_root / "evo_results.json"
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        elapsed = time.time() - t_start
        print(f"\n[EvoRunner] Finished {len(results)} function(s) in {elapsed:.0f}s.")
        print(f"[EvoRunner] Results written to {results_path}")


# Main

def main() -> None:
    args = _parse_args()

    # Graceful Ctrl-C
    signal.signal(signal.SIGINT, lambda _s, _f: sys.exit(0))

    cfg = BenchConfig(args.config)

    if args.function and args.project:
        # Single-function mode
        _run_one(cfg, args.function, args.project, resume=args.resume)
    else:
        # Batch mode
        runner = EvoRunner(
            cfg_path  = args.config,
            processes = args.processes,
            resume    = args.resume,
        )
        runner.run()


if __name__ == "__main__":
    main()
