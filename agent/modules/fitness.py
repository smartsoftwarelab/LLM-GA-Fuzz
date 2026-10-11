"""
fitness.py - Multi-objective fitness scoring for evolved fuzz harnesses.

Parses libFuzzer output logs to extract coverage metrics and computes
a scalar fitness score used for selection in the genetic algorithm.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Fitness weights (must sum to 1.0)
# ---------------------------------------------------------------------------
W_COVERAGE  = 0.45   # edge/block coverage (primary objective)
W_FEATURES  = 0.25   # corpus features (path diversity)
W_EXEC      = 0.10   # execution throughput (harness efficiency)
W_STABILITY = 0.20   # run stability (INITED + DONE reached)

# Normalisation denominators (tune to your target library)
NORM_COVERAGE  = 2000.0   # expected max edges for a single harness
NORM_FEATURES  = 8000.0   # expected max corpus features
NORM_EXEC      = 2000.0   # exec/s considered "fast"

CRASH_BONUS    = 0.60     # extra score for harnesses that find real bugs


@dataclass
class FitnessScores:
    """
    Multi-dimensional fitness vector for one harness genome.

    All raw values come from libFuzzer log parsing.
    ``total()`` returns a scalar in [0, ~1.6] for ranking.
    """

    # --- raw metrics from fuzzing log ---
    coverage: int   = 0       # libFuzzer 'cov:' value (edges covered)
    features: int   = 0       # libFuzzer 'ft:'  value (corpus features)
    exec_per_sec: float = 0.0 # libFuzzer 'exec/s:' (throughput)
    stability: float    = 1.0 # 1.0 = DONE reached, 0.5 = partial, 0.0 = hung

    # --- derived / boolean ---
    crash_found: bool   = False   # harness triggered a real sanitizer error
    compile_ok:  bool   = False   # False → total() == 0

    def total(self) -> float:
        """Scalar fitness used for selection and archiving."""
        if not self.compile_ok:
            return 0.0

        cov_norm   = min(self.coverage    / NORM_COVERAGE,  1.0)
        feat_norm  = min(self.features    / NORM_FEATURES,  1.0)
        exec_norm  = min(self.exec_per_sec / NORM_EXEC,     1.0)

        base = (
            W_COVERAGE  * cov_norm   +
            W_FEATURES  * feat_norm  +
            W_EXEC      * exec_norm  +
            W_STABILITY * self.stability
        )
        return base + (CRASH_BONUS if self.crash_found else 0.0)

    def dominates(self, other: "FitnessScores") -> bool:
        """
        Pareto dominance: self >= other in all objectives AND
        strictly better in at least one.
        """
        objectives = ["coverage", "features", "exec_per_sec"]
        better_in_one = False
        for attr in objectives:
            sv = getattr(self, attr)
            ov = getattr(other, attr)
            if sv < ov:
                return False
            if sv > ov:
                better_in_one = True
        return better_in_one

    def __repr__(self) -> str:
        return (
            f"FitnessScores(cov={self.coverage}, ft={self.features}, "
            f"exec={self.exec_per_sec:.0f}/s, stable={self.stability:.2f}, "
            f"crash={self.crash_found}, total={self.total():.4f})"
        )


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def extract_coverage_from_log(log_path: Path) -> FitnessScores:
    """
    Parse a libFuzzer log file and return a populated FitnessScores.

    Expected log patterns (standard libFuzzer output):
      #2        INITED cov: 16  ft: 16  corp: 1/1b  exec/s: 0  rss: 33Mb
      #8192     pulse  cov: 48  ft: 72  corp: 4/8b  exec/s: 512  rss: 40Mb
      #16384    DONE   cov: 48  ft: 72  corp: 4/8b  exec/s: 512  rss: 40Mb
      stat::number_of_executed_units: 16384
    """
    scores = FitnessScores()

    if not log_path.exists():
        return scores

    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return scores

    if not content.strip():
        return scores

    # ---- coverage (cov:) ----
    cov_matches = re.findall(r"\bcov:\s*(\d+)", content)
    if cov_matches:
        scores.coverage = max(int(x) for x in cov_matches)

    # ---- features (ft:) ----
    ft_matches = re.findall(r"\bft:\s*(\d+)", content)
    if ft_matches:
        scores.features = max(int(x) for x in ft_matches)

    # ---- execution speed (exec/s:) ----
    exec_matches = re.findall(r"\bexec/s:\s*(\d+)", content)
    if exec_matches:
        # use the last reported value (most representative)
        scores.exec_per_sec = float(exec_matches[-1])

    # ---- stability ----
    if "DONE" in content:
        scores.stability = 1.0
    elif "INITED" in content:
        scores.stability = 0.5   # started but didn't finish cleanly
    else:
        scores.stability = 0.0   # never initialised (likely hung or crashed early)

    # ---- crash detection ----
    crash_indicators = [
        "ERROR: AddressSanitizer",
        "ERROR: LeakSanitizer",
        "ERROR: libFuzzer:",
        "== Java Exception",
        "SUMMARY: AddressSanitizer",
    ]
    if any(ind in content for ind in crash_indicators):
        scores.crash_found = True

    scores.compile_ok = True
    return scores
