"""Campaign helpers: seeded stratified target order, per-repetition seeds, run bookkeeping.

Used by scripts/campaign/*.py (sampling, screening, launching, evaluation, gates).
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path
from typing import Any, Optional

import yaml

LANG_LABEL = {"c": "C", "c++": "CPP"}           # benchmark YAML label -> BenchConfig.language
SECRET_RE = re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}")


def load_benchmark(bench_dir: Path) -> list[dict[str, Any]]:
    """One target per benchmark YAML: the project's first function (as funcs_per_project=1)."""
    targets = []
    for f in sorted(Path(bench_dir).glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        fn = next((x for x in data.get("functions", []) if "signature" in x), None)
        if fn is None:
            continue
        targets.append({
            "project": data["project"], "language": str(data.get("language", "")).lower(),
            "signature": fn["signature"], "function": fn.get("name"),
            "target_name": data.get("target_name"), "target_path": data.get("target_path"),
            "yaml": f.name, "yaml_sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
        })
    return targets


def stratified_order(targets: list[dict], seed: int, n: int) -> dict[str, Any]:
    """Seeded random order within each language stratum and proportional quotas for n targets."""
    strata: dict[str, list[dict]] = {}
    for t in sorted(targets, key=lambda t: t["project"]):
        strata.setdefault(t["language"], []).append(t)
    rng = random.Random(seed)
    for lang in sorted(strata):
        rng.shuffle(strata[lang])
    total = sum(len(v) for v in strata.values())
    quota = {lang: round(n * len(v) / total) for lang, v in strata.items()}
    # fix rounding so the quotas add up to n (adjust the largest stratum)
    largest = max(strata, key=lambda k: len(strata[k]))
    quota[largest] += n - sum(quota.values())
    return {"seed": seed, "n": n, "counts": {k: len(v) for k, v in sorted(strata.items())},
            "quota": dict(sorted(quota.items())), "order": {k: v for k, v in sorted(strata.items())}}


def rep_seed(campaign_seed: int, repetition: int) -> int:
    """Base seed of one repetition (evo_gen derives the per-target seed from it)."""
    return int(hashlib.sha256(f"{campaign_seed}:rep{repetition}".encode()).hexdigest()[:8], 16)


def run_key(project: str, repetition: int) -> str:
    return f"{project}_rep{repetition}"


def find_target_dir(save_root: Path, project: str) -> Optional[Path]:
    hits = sorted((Path(save_root) / project.lower()).glob("*/run_manifest.json"))
    return hits[0].parent if hits else None


def manifest_status(target_dir: Optional[Path]) -> Optional[str]:
    if target_dir is None:
        return None
    try:
        return json.loads((target_dir / "run_manifest.json").read_text())["status"]
    except (OSError, KeyError, json.JSONDecodeError):
        return None


def pick_gen0_best(target_dir: Path) -> Optional[dict]:
    """Best compiled generation-0 genome by its recorded in-loop fitness (the non-evolutionary baseline)."""
    genomes = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((target_dir / "evolution" / "gen_000").glob("*.json"))]
    valid = [g for g in genomes if g.get("compile_ok") and g.get("code")]
    return max(valid, key=lambda g: g["fitness"]["total"]) if valid else None


def pick_best_without_bonus(target_dir: Path) -> Optional[dict]:
    """Top genome when the crash bonus is removed from the end-of-run fitness (post-hoc, same run)."""
    from utils.analysis import last_genome_states, recompute_totals
    manifest = json.loads((Path(target_dir) / "run_manifest.json").read_text())
    genomes = last_genome_states(target_dir)
    totals = recompute_totals(genomes, manifest.get("fitness", {}))
    return genomes[max(totals, key=lambda k: totals[k][1])] if totals else None


def pick_final_best(target_dir: Path) -> Optional[dict]:
    hits = sorted((target_dir / "evolution" / "final").glob("best_01_*.json"))
    return json.loads(hits[0].read_text(encoding="utf-8")) if hits else None


def count_http_posts(audit_file: Path) -> Optional[int]:
    if not Path(audit_file).exists():
        return None
    return sum(1 for line in Path(audit_file).read_text(errors="replace").splitlines() if "HTTP Request: POST" in line)


def files_with_secrets(root: Path) -> list[str]:
    hits = []
    for p in Path(root).rglob("*"):
        if p.is_file() and p.stat().st_size < 50_000_000:
            try:
                if SECRET_RE.search(p.read_text(errors="ignore")):
                    hits.append(str(p))
            except OSError:
                continue
    return hits
