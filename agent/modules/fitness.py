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
W_STABILITY = 0.20   # run stability (fuzzing finished normally)

# Normalisation denominators of the original "fixed" mode (kept to reproduce old runs)
NORM_COVERAGE  = 2000.0   # expected max edges for a single harness
NORM_FEATURES  = 8000.0   # expected max corpus features
NORM_EXEC      = 2000.0   # exec/s considered "fast"

CRASH_BONUS    = 0.60     # default lambda: extra score for a crash inside the target library

NORMALIZATION_MODES = ("pool_max", "fixed", "rrf")

# Near-init crash (cf. OSS-Fuzz-Gen FP_NEAR_INIT_CRASH, ossfuzz_gen/build_runner.py:46,240): the trial
# crashed and averaged at most this many executions per fork job, i.e. the harness fails on (almost)
# any input. Fork status lines print "#<executed units of finished jobs> ... job: <id>", and the run
# still ends with "INFO: exiting:". Such a trial is a harness failure (no bonus, stability 0). None = off.
NEAR_INIT_EXECS_PER_JOB = 3
_FORK_STATUS_RE = re.compile(r"^#(\d+):\s+cov:.*?\bjob:\s*(\d+)", re.MULTILINE)

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


# ---------------------------------------------------------------------------
# Crash vs. harness-failure classification
# ---------------------------------------------------------------------------

# Events that are defects of the harness/run, never a library bug (no crash bonus).
HARNESS_FAILURE_TYPES = ("oom", "timeout", "deadly_signal", "const_input_overwrite", "leak", "other_libfuzzer")

_EVENT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("oom",                   re.compile(r"ERROR: libFuzzer: out-of-memory")),
    ("timeout",               re.compile(r"ERROR: libFuzzer: timeout")),
    ("deadly_signal",         re.compile(r"ERROR: libFuzzer: deadly signal")),
    ("const_input_overwrite", re.compile(r"ERROR: libFuzzer: fuzz target overwrites its const input")),
    ("other_libfuzzer",       re.compile(r"ERROR: libFuzzer: (?!out-of-memory|timeout|deadly signal|"
                                         r"fuzz target overwrites its const input)")),
    ("leak",                  re.compile(r"ERROR: LeakSanitizer")),
    # candidate library defects: decided by stack location
    ("sanitizer",             re.compile(r"ERROR: (?:AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer)"
                                         r"|runtime error: |== Java Exception")),
)

# "#3 0x55d0... in func_name /src/proj/file.c:12:3"
_FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+.+?\s+(/\S+?):\d+", re.MULTILINE)
# fuzzer / sanitizer runtime and system sources, never the target library
_RUNTIME_PREFIXES = ("/src/llvm-project/", "/src/libfuzzer/", "/src/aflplusplus/", "/usr/")


def classify_events(content: str) -> dict[str, int]:
    """Count crash / failure events in a libFuzzer log by type (types with 0 omitted)."""
    counts = {name: len(pat.findall(content)) for name, pat in _EVENT_PATTERNS}
    return {k: v for k, v in counts.items() if v}


def crash_location(report: str, scope_root: Optional[str], harness_path: Optional[str]) -> str:
    """'library' if any stack frame lies in the target library's source tree (scope_root),
    excluding the harness file and runtime frames; else 'harness' if a frame is in the harness;
    'other' if frames exist elsewhere; 'unknown' if the report has no symbolized frames."""
    paths = [p for p in _FRAME_RE.findall(report) if not p.startswith(_RUNTIME_PREFIXES)]
    if not paths:
        return "unknown"
    if scope_root and any(p.startswith(scope_root) and p != harness_path for p in paths):
        return "library"
    if harness_path and harness_path in paths:
        return "harness"
    return "other"


# ---------------------------------------------------------------------------
# Normalisation (process-wide, configured per run by EvoISSTAFuzzer)
# ---------------------------------------------------------------------------

class FitnessConfig:
    """How objective terms are normalised and how large the crash bonus is.

    pool_max: x / max(x over all harnesses evaluated so far in this run)
    fixed:    min(x / NORM_*, 1)  (original behaviour; saturates on large targets)
    rrf:      weighted reciprocal-rank fusion, (k+1)/(k+rank) per objective over the same pool
    """

    def __init__(self, mode: str = "fixed", crash_bonus: float = CRASH_BONUS, rrf_k: int = 60,
                 near_init_execs: Optional[float] = NEAR_INIT_EXECS_PER_JOB) -> None:
        if mode not in NORMALIZATION_MODES:
            raise ValueError(f"fitness_normalization must be one of {NORMALIZATION_MODES}, got {mode!r}")
        self.mode = mode
        self.crash_bonus = float(crash_bonus)
        self.rrf_k = int(rrf_k)
        self.near_init_execs = None if near_init_execs is None else float(near_init_execs)
        self.pool: dict[str, list[float]] = {"coverage": [], "features": [], "exec_per_sec": []}

    def observe(self, scores: "FitnessScores") -> None:
        if scores.status != STATUS_OK:
            return
        for k in self.pool:
            v = getattr(scores, k)
            if v is not None:
                self.pool[k].append(float(v))

    def term(self, objective: str, value: Optional[float]) -> float:
        v = float(value or 0)
        if self.mode == "fixed":
            norm = {"coverage": NORM_COVERAGE, "features": NORM_FEATURES, "exec_per_sec": NORM_EXEC}[objective]
            return min(v / norm, 1.0)
        values = self.pool[objective]
        if self.mode == "pool_max":
            top = max(values) if values else 0.0
            return min(v / top, 1.0) if top > 0 else 0.0
        rank = 1 + sum(1 for x in values if x > v)          # rrf
        return (self.rrf_k + 1) / (self.rrf_k + rank)

    def state(self) -> dict:
        return {"mode": self.mode, "crash_bonus": self.crash_bonus, "rrf_k": self.rrf_k,
                "near_init_execs_per_job": self.near_init_execs,
                "n_observed": len(self.pool["coverage"]),
                "max": {k: (max(v) if v else None) for k, v in self.pool.items()}}


_CONFIG = FitnessConfig()


def configure_fitness(mode: str, crash_bonus: float = CRASH_BONUS, rrf_k: int = 60,
                      near_init_execs: Optional[float] = NEAR_INIT_EXECS_PER_JOB) -> FitnessConfig:
    """Start a fresh normalisation pool for one run."""
    global _CONFIG
    _CONFIG = FitnessConfig(mode, crash_bonus, rrf_k, near_init_execs)
    return _CONFIG


def fitness_config() -> FitnessConfig:
    return _CONFIG


@dataclass
class FitnessScores:
    """
    Multi-dimensional fitness vector for one harness genome.

    All raw values come from libFuzzer log parsing.
    ``total()`` returns a scalar in [0, 1 + lambda] for ranking.
    """

    # --- raw metrics from fuzzing log (None = not measured, see status) ---
    coverage: Optional[int]   = None      # libFuzzer 'cov:' value (edges covered)
    features: Optional[int]   = None      # libFuzzer 'ft:'  value (corpus features)
    exec_per_sec: Optional[float] = None  # libFuzzer 'exec/s:' (throughput)
    stability: Optional[float]    = None  # 1.0 = finished normally, 0.5 = partial, 0.0 = hung / near-init crash
    execs_per_job: Optional[float] = None # fork mode: executed units / jobs (None for non-fork logs)

    # --- derived / boolean ---
    crash_found: bool   = False   # any crash or harness-failure event in the trial (informational)
    compile_ok:  bool   = False   # False → total() == 0

    status: str = STATUS_NOT_EVALUATED
    error_message: Optional[str] = None

    # --- crash classification (crash bonus only for library_crash) ---
    crash_events: dict = field(default_factory=dict)   # event type -> count
    library_crash: bool = False                         # sanitizer crash with a frame in the library
    crash_location: Optional[str] = None                # library | harness | other | unknown
    discard_reason: Optional[str] = None                # why a crash / trial earned no bonus
    near_init_crash: bool = False                       # crashed on (almost) every input (fork mode)

    def total(self) -> float:
        """Scalar fitness used for selection and archiving."""
        if not self.compile_ok:
            return 0.0
        cfg = _CONFIG
        bonus = cfg.crash_bonus if self.library_crash else 0.0
        if self.status != STATUS_OK:
            # No statistics were measured: the objective terms contribute nothing to
            # selection. The record keeps None (with the status), not a fake 0.
            return bonus

        base = (
            W_COVERAGE  * cfg.term("coverage", self.coverage)          +
            W_FEATURES  * cfg.term("features", self.features)          +
            W_EXEC      * cfg.term("exec_per_sec", self.exec_per_sec)  +
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

    def apply_crash_location(self, location: str) -> None:
        """Set crash_location / library_crash / discard_reason for a trial with sanitizer events."""
        self.crash_location = location
        self.library_crash = location == "library"
        self.discard_reason = None if self.library_crash else {
            "harness": "crash_in_harness", "other": "crash_outside_library",
        }.get(location, "crash_location_unknown")
        self.apply_near_init_rule()

    def apply_near_init_rule(self) -> None:
        """A trial that crashed and ran <= near_init_execs executions per fork job exercised a
        harness that fails on (almost) any input: harness failure, no crash bonus, stability 0."""
        limit = _CONFIG.near_init_execs
        if limit is None or self.execs_per_job is None or not self.crash_events or self.execs_per_job > limit:
            return
        self.near_init_crash = True
        self.library_crash = False
        self.stability = 0.0
        prior = self.discard_reason if (self.discard_reason or "").startswith("harness_failure:") else None
        self.discard_reason = f"{prior},near_init_crash" if prior else "harness_failure:near_init_crash"

    def __repr__(self) -> str:
        exec_s = "None" if self.exec_per_sec is None else f"{self.exec_per_sec:.0f}"
        stable = "None" if self.stability is None else f"{self.stability:.2f}"
        return (
            f"FitnessScores(status={self.status}, cov={self.coverage}, ft={self.features}, "
            f"exec={exec_s}/s, stable={stable}, "
            f"crash={self.crash_found}, library_crash={self.library_crash}, total={self.total():.4f})"
        )


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def extract_coverage_from_log(log_path: Path, scope_root: Optional[str] = None,
                              harness_path: Optional[str] = None) -> FitnessScores:
    """
    Parse a libFuzzer log file and return a populated FitnessScores.

    Expected log patterns (standard libFuzzer output):
      #2        INITED cov: 16  ft: 16  corp: 1/1b  exec/s: 0  rss: 33Mb
      #8192     pulse  cov: 48  ft: 72  corp: 4/8b  exec/s: 512  rss: 40Mb
      #16384    DONE   cov: 48  ft: 72  corp: 4/8b  exec/s: 512  rss: 40Mb
      stat::number_of_executed_units: 16384

    With -fork=1 the status lines read "#N: cov: X ft: Y corp: Z exec/s: E ..." and a
    normal finish ends with "INFO: exiting: ...". Fork-mode logs carry no stack traces,
    so the crash location stays 'unknown' until the crash input is reproduced.
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

    # ---- fork-mode executions per job (last status line; #N = executed units of finished jobs) ----
    fork_status = _FORK_STATUS_RE.findall(content)
    if fork_status:
        runs, jobs = (int(x) for x in fork_status[-1])
        jobs = max(jobs, max(int(j) for _, j in fork_status))   # job ids can finish out of order
        scores.execs_per_job = runs / jobs if jobs else None

    # ---- stability ----
    if "DONE" in content or "INFO: exiting:" in content:
        scores.stability = 1.0   # finished normally (non-fork DONE / fork-mode exit line)
    elif "INITED" in content or cov_matches:
        scores.stability = 0.5   # started but didn't finish cleanly
    else:
        scores.stability = 0.0   # never initialised (likely hung or crashed early)

    # ---- crash / harness-failure classification ----
    scores.crash_events = classify_events(content)
    scores.crash_found = bool(scores.crash_events)
    failures = sorted(t for t in scores.crash_events if t in HARNESS_FAILURE_TYPES)
    if failures:
        scores.discard_reason = "harness_failure:" + ",".join(failures)
    if "sanitizer" in scores.crash_events:
        scores.apply_crash_location(crash_location(content, scope_root, harness_path))
    else:
        scores.apply_near_init_rule()

    scores.compile_ok = True
    return scores
