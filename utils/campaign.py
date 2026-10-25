"""Campaign helpers: seeded stratified target order, per-repetition seeds, run bookkeeping.

Used by scripts/campaign/*.py (sampling, screening, launching, evaluation, gates).
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

import yaml

LANG_LABEL = {"c": "C", "c++": "CPP"}           # benchmark YAML label -> BenchConfig.language
SECRET_RE = re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}")
# per-run OSS-Fuzz project copies made by FuzzENV: run<n>_<16 lowercase letters>
RUN_PROJECT_RE = re.compile(r"^run\d+_[a-z]{16}$")


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


def first_initial_error(target_dir: Optional[Path]) -> Optional[str]:
    """First recorded initial-generation error of a run (why a run aborted)."""
    if target_dir is None:
        return None
    try:
        attempts = json.loads((target_dir / "run_manifest.json").read_text()).get("initial_attempts") or []
    except (OSError, json.JSONDecodeError):
        return None
    return next((a["error"][:300] for a in attempts if a.get("error")), None)


def free_gb(paths: list) -> Optional[float]:
    """Smallest free space (GB) over the existing paths (output dir, oss-fuzz, docker root)."""
    free = [shutil.disk_usage(p).free / 1e9 for p in map(Path, paths) if p.exists()]
    return min(free) if free else None


def cleanup_run_workspace(oss_fuzz_dir: Path, new_project_name: str, remove_image: bool = True) -> list[str]:
    """Remove the per-run OSS-Fuzz copy of a project: docker image gcr.io/oss-fuzz/<name> and
    projects/, build/out/, build/work/ <name>. Results (corpus, logs, coverage) live elsewhere.
    Refuses any name that is not a FuzzENV run name, so real projects are never touched."""
    if not RUN_PROJECT_RE.match(new_project_name):
        raise ValueError(f"refusing to clean non-run project {new_project_name!r}")
    removed = []
    if remove_image:
        try:
            res = subprocess.run(["docker", "rmi", "-f", f"gcr.io/oss-fuzz/{new_project_name}"],
                                 capture_output=True, text=True, timeout=300)
            if res.returncode == 0:
                removed.append(f"image gcr.io/oss-fuzz/{new_project_name}")
        except (OSError, subprocess.SubprocessError):
            pass
    for sub in ("projects", "build/out", "build/work"):
        d = Path(oss_fuzz_dir) / sub / new_project_name
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed.append(str(d))
    return removed


def run_fuzzer_info(target_dir: Path, bench_dir: Path, project: str) -> tuple[Optional[dict], str]:
    """Fuzz target for evaluating a run's harnesses: the one an initial harness was validated with,
    else the benchmark target (target_name / target_path), which evolution compiles every genome
    into (evo_gen.py: first harness pair = benchmark target)."""
    hit = next(iter(sorted(Path(target_dir).glob("run[0-9]*_*/fuzzer_info.json"))), None)
    if hit is not None:
        return json.loads(hit.read_text()), "validated_initial_harness"
    bench = Path(bench_dir) / f"{project}.yaml"
    if not bench.exists():
        return None, "missing"
    data = yaml.safe_load(bench.read_text())
    if not data.get("target_name") or not data.get("target_path"):
        return None, "missing"
    return {"fuzzer_name": data["target_name"], "fuzzer_path": data["target_path"]}, "benchmark_yaml"


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
