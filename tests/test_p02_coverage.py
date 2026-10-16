"""PATCH 2 unit tests: structured coverage results; failures are never stored as 0.

Pure-Python parts only. The Docker/llvm-cov path is checked by
scripts/p02_coverage_reference.sh against tests/p02_reference_expected.md.
"""
import json
from pathlib import Path

import pytest

from agent.modules.fitness import (
    STATUS_NO_LOG, STATUS_NO_STATS, STATUS_OK, CRASH_BONUS,
    FitnessScores, extract_coverage_from_log, prompt_value,
)
from agent.modules.population import Archive, HarnessGenome
from agent_tools.fuzz_tools.coverage_result import CoverageResult, CoverageStatus
from agent_tools.fuzz_tools.llvm_cov import library_scope_root, parse_replay_tsv, result_from_export
from agent_tools.results_analysis import get_evaluation_results

FIX = Path(__file__).parent / "fixtures" / "p02"
HARNESS = "/src/lib/fuzz/harness.c"


def _summary(branches, functions=(1, 1), lines=(10, 5), regions=(8, 4)):
    def m(t):
        return {"count": t[0], "covered": t[1], "percent": 0}
    return {"branches": m(branches), "functions": m(functions), "lines": m(lines), "regions": m(regions)}


def _export(files):
    return {"type": "llvm.coverage.json.export", "version": "2.0.1",
            "data": [{"files": [{"filename": n, "summary": s} for n, s in files],
                      "totals": _summary((100, 10))}]}


# ---- CoverageResult -------------------------------------------------------

@pytest.mark.parametrize("status", [s for s in CoverageStatus
                                    if s not in (CoverageStatus.OK, CoverageStatus.NO_COVERAGE)])
def test_failure_statuses_store_null_not_zero(status):
    r = CoverageResult(status, "branches", covered=0, total=123, error_message="x")
    d = r.to_dict()
    assert d["covered"] is None and d["total"] is None and d["percent"] is None
    assert d["status"] == status.value


def test_measured_status_requires_numbers():
    with pytest.raises(ValueError):
        CoverageResult(CoverageStatus.OK, "branches")
    r = CoverageResult(CoverageStatus.NO_COVERAGE, "branches", covered=0, total=6)
    assert r.to_dict()["covered"] == 0 and r.percent == 0.0


# ---- scope + export parsing -----------------------------------------------

def test_library_scope_root():
    assert library_scope_root("/src/cjson/fuzzing/cjson_read_fuzzer.c", "cjson") == "/src/cjson/"
    assert library_scope_root("/src/ada-url/fuzz/parse.cc", "ada-url") == "/src/ada-url/"
    assert library_scope_root("/src/harness.c", "matio") == "/src/matio/"


def test_export_scoped_sum_excludes_harness_and_other_trees():
    exp = _export([
        ("/src/lib/a.c", _summary((6, 4))),
        ("/src/lib/b.c", _summary((4, 1))),
        (HARNESS, _summary((50, 50))),            # harness: excluded
        ("/src/zlib/inflate.c", _summary((90, 90))),  # dependency: outside scope
    ])
    r = result_from_export(exp, "/src/lib/", {HARNESS}, "branches")
    assert r.status == CoverageStatus.OK
    assert (r.covered, r.total) == (5, 10)
    assert r.metrics["files_in_scope"] == ["/src/lib/a.c", "/src/lib/b.c"]
    assert r.metrics["scope"]["functions"] == {"covered": 2, "count": 2}
    assert r.metrics["whole_binary"]["branches"] == {"covered": 10, "count": 100}


def test_export_zero_covered_is_no_coverage_with_real_zero():
    r = result_from_export(_export([("/src/lib/a.c", _summary((6, 0)))]), "/src/lib/", set(), "branches")
    assert r.status == CoverageStatus.NO_COVERAGE and (r.covered, r.total) == (0, 6)


@pytest.mark.parametrize("export, why", [
    (_export([("/src/other/a.c", _summary((6, 3)))]), "no source files"),
    ({"data": [{"files": [{"filename": "/src/lib/a.c"}]}]}, "malformed"),
    ({"nothing": 1}, "malformed"),
    (_export([("/src/lib/a.c", {"lines": {"count": 3, "covered": 1}})]), "not present"),
    (_export([("/src/lib/a.c", _summary((0, 0)))]), "zero instrumented"),
])
def test_export_problems_are_parse_failed(export, why):
    r = result_from_export(export, "/src/lib/", set(), "branches")
    assert r.status == CoverageStatus.PARSE_FAILED
    assert r.covered is None and r.total is None
    assert why in r.error_message


def test_parse_replay_tsv(tmp_path):
    f = tmp_path / "replay.tsv"
    f.write_text("a\t0\nb\t1\nc\t137\n\n")
    assert parse_replay_tsv(f) == (3, 2)


# ---- evolution-loop fitness (path A) --------------------------------------

def test_fork_mode_log_is_measured():
    s = extract_coverage_from_log(FIX / "fork_ok.log")
    assert s.status == STATUS_OK
    assert (s.coverage, s.features, s.exec_per_sec) == (2920, 9457, 34776.0)


def test_log_without_stats_records_none_not_zero():
    s = extract_coverage_from_log(FIX / "no_stats.log")
    assert s.status == STATUS_NO_STATS
    assert s.coverage is None and s.features is None and s.exec_per_sec is None
    s.compile_ok = True
    assert s.total() == 0.0
    s.library_crash = True          # PATCH 4: the bonus requires a crash inside the library
    assert s.total() == CRASH_BONUS


def test_missing_and_empty_log_are_no_log(tmp_path):
    assert extract_coverage_from_log(tmp_path / "missing.log").status == STATUS_NO_LOG
    empty = tmp_path / "empty.log"
    empty.write_text("   \n")
    s = extract_coverage_from_log(empty)
    assert s.status == STATUS_NO_LOG and s.coverage is None


def test_prompt_rendering_unchanged_for_missing_stats():
    assert prompt_value(None) == "0"
    assert prompt_value(2920) == "2920"


def test_genome_record_and_archive_stats_keep_null():
    g = HarnessGenome.make("int x;", 0, [], "INITIAL")
    g.compile_ok = True
    g.fitness = FitnessScores(compile_ok=True, status=STATUS_NO_STATS)
    d = json.loads(json.dumps(g.to_dict()))
    assert d["fitness"]["coverage"] is None and d["fitness"]["status"] == STATUS_NO_STATS
    a = Archive(capacity=4)
    a.add(g)
    assert a.coverage_stats() == {"max": None, "mean": None, "min": None}
    assert "cov_mean=None" in repr(a)


# ---- evaluation_results.json reader ---------------------------------------

def test_get_evaluation_results_counts_statuses(tmp_path):
    ok = CoverageResult(CoverageStatus.OK, "branches", covered=4, total=6).to_dict()
    bad = CoverageResult(CoverageStatus.BUILD_FAILED, "branches", error_message="x").to_dict()
    (tmp_path / "evaluation_results.json").write_text(json.dumps({
        "p+f1": {"coverage": ok, "fuzz_result": "NoError"},
        "p+f2": {"coverage": bad, "fuzz_result": "NOT_RUN"},
    }))
    assert get_evaluation_results(tmp_path) == {"OK": 1, "BUILD_FAILED": 1}


def test_get_evaluation_results_rejects_legacy_format(tmp_path):
    (tmp_path / "evaluation_results.json").write_text(json.dumps({"p+f": [0, 0, 0, 0.0, 0.0]}))
    with pytest.raises(ValueError, match="legacy"):
        get_evaluation_results(tmp_path)
