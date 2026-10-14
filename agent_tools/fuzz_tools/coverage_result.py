"""Structured outcome of one coverage measurement.

A failed measurement is never stored as 0: only OK and NO_COVERAGE carry
numbers, every other status stores None for covered/total.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class CoverageStatus(str, Enum):
    OK = "OK"                      # measured, covered > 0
    NO_COVERAGE = "NO_COVERAGE"    # measured, covered == 0 (a real zero)
    EMPTY_CORPUS = "EMPTY_CORPUS"  # fuzzing produced no inputs to replay
    BUILD_FAILED = "BUILD_FAILED"  # fuzzing or coverage build failed
    TOOL_FAILED = "TOOL_FAILED"    # docker / replay / llvm-profdata / llvm-cov failed
    PARSE_FAILED = "PARSE_FAILED"  # llvm-cov output missing, malformed, or nothing in scope
    TIMEOUT = "TIMEOUT"            # replay exceeded coverage_total_timeout


MEASURED_STATUSES = frozenset({CoverageStatus.OK, CoverageStatus.NO_COVERAGE})


@dataclass
class CoverageResult:
    status: CoverageStatus
    metric: str                               # llvm-cov summary key: branches | regions | lines | functions
    covered: Optional[int] = None             # covered units of `metric` inside scope_root
    total: Optional[int] = None               # instrumented units of `metric` inside scope_root
    raw_output_path: Optional[str] = None     # directory with build log, replay log, export.json, profdata
    error_message: Optional[str] = None
    scope_root: Optional[str] = None          # source-tree prefix counted as "the library"
    inputs_replayed: Optional[int] = None
    inputs_failed: Optional[int] = None       # replays with non-zero exit (their coverage may be missing)
    metrics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = CoverageStatus(self.status)
        if self.status in MEASURED_STATUSES:
            if not isinstance(self.covered, int) or not isinstance(self.total, int):
                raise ValueError(f"{self.status.value} requires integer covered/total")
        else:
            self.covered = None
            self.total = None

    @property
    def measured(self) -> bool:
        return self.status in MEASURED_STATUSES

    @property
    def percent(self) -> Optional[float]:
        if not self.measured or not self.total:
            return None
        return round(self.covered / self.total * 100, 2)  # type: ignore[operator]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["percent"] = self.percent
        return d
