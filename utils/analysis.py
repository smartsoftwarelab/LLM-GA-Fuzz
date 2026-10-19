"""Statistics for the campaign analysis (numpy only; the mixed model lives in the script).

Definitions used in every table of the paper:
- coverage   : llvm-cov branch coverage of the target library, covered / total (percent).
- improvement: per run, r = (final_best - gen0_best) / gen0_best on covered branches; a target's
               improvement is the median r over its repetitions; the campaign improvement is the
               median of target medians, with a hierarchical bootstrap CI (targets, then runs).
- effect size: Vargha-Delaney A12(final, gen0) per target over repetitions: probability that a
               random final-best run covers more branches than a random gen0-best run (ties 0.5).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import numpy as np


def a12(x: list[float], y: list[float]) -> Optional[float]:
    if not x or not y:
        return None
    gt = sum(1.0 for a in x for b in y if a > b)
    eq = sum(0.5 for a in x for b in y if a == b)
    return (gt + eq) / (len(x) * len(y))


def rel_improvement(gen0: Optional[float], final: Optional[float]) -> Optional[float]:
    if gen0 is None or final is None or gen0 == 0:
        return None
    return (final - gen0) / gen0


def hier_bootstrap_median(per_target: dict[str, list[float]], n_boot: int = 10000,
                          seed: int = 0, alpha: float = 0.05) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """Median of per-target medians and its (1-alpha) CI: resample targets, then runs within each."""
    groups = [np.asarray(v, dtype=float) for v in per_target.values() if len(v)]
    if not groups:
        return None, None, None
    point = float(np.median([np.median(g) for g in groups]))
    rng = np.random.default_rng(seed)
    stats = np.empty(n_boot)
    for i in range(n_boot):
        picked = rng.integers(0, len(groups), len(groups))
        stats[i] = np.median([np.median(rng.choice(groups[j], len(groups[j]))) for j in picked])
    lo, hi = np.quantile(stats, [alpha / 2, 1 - alpha / 2])
    return point, float(lo), float(hi)


def median_iqr(values: list[float]) -> tuple[Optional[float], Optional[float], Optional[float]]:
    if not values:
        return None, None, None
    q1, med, q3 = np.quantile(np.asarray(values, dtype=float), [0.25, 0.5, 0.75])
    return float(med), float(q1), float(q3)


def _cov(rec: dict) -> dict:
    return (rec or {}).get("coverage") or {}


def load_runs(out_dir: Path, arm: str) -> list[dict[str, Any]]:
    """One row per completed run with evaluation, usage, timing and crash statistics."""
    rows = []
    for mp in sorted(Path(out_dir).glob("rep*/*/*/run_manifest.json")):
        m = json.loads(mp.read_text())
        d = mp.parent
        ev_path = d / "eval" / "eval_results.json"
        if m.get("status") != "completed" or not ev_path.exists():
            continue
        ev = json.loads(ev_path.read_text())["results"]
        g0, fb = _cov(ev.get("gen0_best")), _cov(ev.get("final_best"))
        usage = [json.loads(x) for x in (d / "usage_log.jsonl").read_text().splitlines()] if (d / "usage_log.jsonl").exists() else []
        genomes = {}
        for gp in sorted(d.glob("evolution/gen_*/*.json")):      # last saved state of each genome
            g = json.loads(gp.read_text(encoding="utf-8"))
            genomes[g["genome_id"]] = g
        fit = [g["fitness"] for g in genomes.values()]
        rules = [g.get("meta", {}).get("strategy_rule") for g in genomes.values() if g.get("meta", {}).get("strategy_rule")]
        rows.append({
            "arm": arm, "project": m["project"], "rep": m["repetition_index"], "run_id": m["run_id"],
            "metric": g0.get("metric") or fb.get("metric"),
            "gen0_status": g0.get("status"), "gen0_covered": g0.get("covered"), "gen0_total": g0.get("total"),
            "gen0_pct": g0.get("percent"),
            "final_status": fb.get("status"), "final_covered": fb.get("covered"), "final_total": fb.get("total"),
            "final_pct": fb.get("percent"),
            "final_is_gen0": bool(ev.get("final_best", {}).get("reused_from")),
            "generations_run": m.get("generations_run"),
            "secs_initial_generation": m["phases"].get("initial_generation", {}).get("seconds"),
            "secs_initial_evaluation": m["phases"].get("initial_evaluation", {}).get("seconds"),
            "secs_evolution": m["phases"].get("evolution", {}).get("seconds"),
            "llm_requests": len(usage),
            "llm_errors": sum(1 for u in usage if u["outcome"] != "ok"),
            "prompt_tokens": sum(u["prompt_tokens"] or 0 for u in usage),
            "cached_prompt_tokens": sum(u["cached_prompt_tokens"] or 0 for u in usage),
            "completion_tokens": sum(u["completion_tokens"] or 0 for u in usage),
            "usage_missing": sum(1 for u in usage if u["usage_source"] == "missing" and u["outcome"] == "ok"),
            "genomes": len(genomes),
            "genomes_compiled": sum(1 for g in genomes.values() if g.get("compile_ok")),
            "library_crash_genomes": sum(1 for f in fit if f.get("library_crash")),
            "harness_failure_genomes": sum(1 for f in fit if str(f.get("discard_reason") or "").startswith("harness_failure")),
            "rule_low_stability": rules.count("low_stability"), "rule_path_plateau": rules.count("path_plateau"),
            "rule_uniform": rules.count("uniform"), "rule_random": rules.count("random"),
            "bonus_changed_top": _bonus_changed_top(genomes, m.get("fitness", {}).get("crash_bonus_lambda", 0.0)),
        })
    return rows


def _bonus_changed_top(genomes: dict, lam: float) -> Optional[bool]:
    """Post-hoc: would the top genome differ without the crash bonus (totals as last saved)?"""
    valid = [g for g in genomes.values() if g.get("compile_ok")]
    if not valid or not lam:
        return None if not valid else False
    top = max(valid, key=lambda g: g["fitness"]["total"])
    top_wo = max(valid, key=lambda g: g["fitness"]["total"] - (lam if g["fitness"].get("library_crash") else 0.0))
    return top["genome_id"] != top_wo["genome_id"]
