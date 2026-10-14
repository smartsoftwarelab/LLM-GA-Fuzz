"""
fitness.py - Multi-objective fitness scoring for evolved fuzz harnesses.

Parses libFuzzer output logs to extract coverage metrics and computes
a scalar fitness score used for selection in the genetic algorithm.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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

# Trial outcome stored with every FitnessScores. Only STATUS_OK carries measured
# libFuzzer statistics; every other status stores None for them, never 0.
STATUS_OK             = "OK"
STATUS_NOT_EVALUATED  = "NOT_EVALUATED"
STATUS_COMPILE_FAILED = "COMPILE_FAILED"
STATUS_NO_LOG         = "NO_LOG"          # fuzz log missing, unreadable or empty
STATUS_NO_STATS       = "NO_STATS"        # log present but no libFuzzer 'cov:' status line
STATUS_EVAL_SKIPPED   = "EVAL_SKIPPED"    # evaluation environment early exit
STATUS_EVAL_ERROR     = "EVAL_ERROR"      # exception during compile / trial


def prompt_value(value: Optional[float]) -> str:
    """Render a statistic for LLM prompts. Missing statistics are shown as 0, exactly
    as before statuses were recorded, so prompt text (an experimental input) is unchanged."""
    return str(0 if value is None else value)


@dataclass
class FitnessScores:
    """
    Multi-dimensional fitness vector for one harness genome.

    All raw values come from libFuzzer log parsing.
    ``total()`` returns a scalar in [0, ~1.6] for ranking.
    """

    # --- raw metrics from fuzzing log (None = not measured, see status) ---
    coverage: Optional[int]   = None      # libFuzzer 'cov:' value (edges covered)
    features: Optional[int]   = None      # libFuzzer 'ft:'  value (corpus features)
    exec_per_sec: Optional[float] = None  # libFuzzer 'exec/s:' (throughput)
    stability: Optional[float]    = None  # 1.0 = DONE reached, 0.5 = partial, 0.0 = hung

    # --- derived / boolean ---
    crash_found: bool   = False   # harness triggered a real sanitizer error
    compile_ok:  bool   = False   # False → total() == 0

    status: str = STATUS_NOT_EVALUATED
    error_message: Optional[str] = None

    def total(self) -> float:
        """Scalar fitness used for selection and archiving."""
        if not self.compile_ok:
            return 0.0
        bonus = CRASH_BONUS if self.crash_found else 0.0
        if self.status != STATUS_OK:
            # No statistics were measured: the objective terms contribute nothing to
            # selection. The record keeps None (with the status), not a fake 0.
            return bonus

        cov_norm   = min(self.coverage / NORM_COVERAGE,             1.0)  # type: ignore[operator]
        feat_norm  = min((self.features or 0) / NORM_FEATURES,      1.0)
        exec_norm  = min((self.exec_per_sec or 0.0) / NORM_EXEC,    1.0)

        base = (
            W_COVERAGE  * cov_norm   +
            W_FEATURES  * feat_norm  +
            W_EXEC      * exec_norm  +
            W_STABILITY * (self.stability or 0.0)
        )
        return base + bonus

    def dominates(self, other: "FitnessScores") -> bool:
        """
        Pareto dominance: self >= other in all objectives AND
        strictly better in at least one. Unmeasured scores dominate nothing.
        """
        if self.status != STATUS_OK or other.status != STATUS_OK:
            return False
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
        exec_s = "None" if self.exec_per_sec is None else f"{self.exec_per_sec:.0f}"
        stable = "None" if self.stability is None else f"{self.stability:.2f}"
        return (
            f"FitnessScores(status={self.status}, cov={self.coverage}, ft={self.features}, "
            f"exec={exec_s}/s, stable={stable}, "
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

    With -fork=1 the status lines read "#N: cov: X ft: Y corp: Z exec/s: E ...".
    Returns status NO_LOG / NO_STATS (statistics None) when nothing was measured.
    """
    scores = FitnessScores(status=STATUS_NO_LOG)

    if not log_path.exists():
        scores.error_message = f"fuzz log not found: {log_path}"
        return scores

    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        scores.error_message = f"cannot read fuzz log: {exc}"
        return scores

    if not content.strip():
        scores.error_message = "fuzz log is empty"
        return scores

    # ---- coverage (cov:) ----
    cov_matches = re.findall(r"\bcov:\s*(\d+)", content)
    if cov_matches:
        scores.coverage = max(int(x) for x in cov_matches)
        scores.status = STATUS_OK
    else:
        scores.status = STATUS_NO_STATS
        scores.error_message = "no libFuzzer 'cov:' status line in fuzz log"

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
