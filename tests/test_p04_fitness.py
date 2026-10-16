"""PATCH 4: crash vs harness failure, configurable crash bonus, non-saturating normalisation."""
from pathlib import Path

import pytest

from agent.modules import fitness as F
from agent.modules.fitness import (STATUS_OK, FitnessScores, classify_events, configure_fitness,
                                   crash_location, extract_coverage_from_log)

FIX = Path(__file__).parent / "fixtures"
GPAC_ROOT = "/src/gpac/"
GPAC_HARNESS = "/src/gpac/testsuite/oss-fuzzers/fuzz_m2ts_probe.c"


@pytest.fixture(autouse=True)
def _fresh_config():
    configure_fitness("fixed")
    yield
    configure_fitness("fixed")


def _parse(name):
    return extract_coverage_from_log(FIX / "p04" / name, scope_root=GPAC_ROOT, harness_path=GPAC_HARNESS)


# ---- acceptance criteria ----------------------------------------------------

def test_out_of_memory_is_not_a_vulnerability():
    s = _parse("oom.log")
    assert s.crash_events == {"oom": 1}
    assert s.library_crash is False
    assert s.discard_reason == "harness_failure:oom"
    assert s.total() < F.CRASH_BONUS   # no bonus


def test_real_in_library_sanitizer_crash_is_counted():
    s = _parse("library_crash.log")
    assert s.crash_events == {"sanitizer": 1}
    assert (s.crash_location, s.library_crash, s.discard_reason) == ("library", True, None)
    assert s.total() >= F.CRASH_BONUS


def test_harness_only_crash_is_not_counted():
    s = _parse("harness_crash.log")
    assert (s.crash_location, s.library_crash, s.discard_reason) == ("harness", False, "crash_in_harness")


def test_fork_log_without_stack_is_unknown_until_reproduced():
    s = _parse("fork_sanitizer.log")
    assert s.crash_events == {"sanitizer": 1, "leak": 1}
    assert (s.crash_location, s.library_crash, s.discard_reason) == ("unknown", False, "crash_location_unknown")
    assert s.stability == 1.0                       # fork-mode "INFO: exiting:" = normal finish
    s.apply_crash_location("library")               # what a reproduced library stack yields
    assert s.library_crash and s.discard_reason is None


@pytest.mark.parametrize("line, kind", [
    ("==1== ERROR: libFuzzer: timeout after 31 seconds", "timeout"),
    ("==1== ERROR: libFuzzer: deadly signal", "deadly_signal"),
    ("==1== ERROR: libFuzzer: fuzz target overwrites its const input", "const_input_overwrite"),
    ("==1== ERROR: libFuzzer: fuzz target exited", "other_libfuzzer"),
    ("==1==ERROR: LeakSanitizer: detected memory leaks", "leak"),
    ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0", "sanitizer"),
    ("src/x.c:3:5: runtime error: signed integer overflow", "sanitizer"),
])
def test_event_types(line, kind):
    assert classify_events(line) == {kind: 1}


def test_runtime_frames_are_ignored():
    rep = "    #0 0x1 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/x.cpp:1:1\n"
    assert crash_location(rep, GPAC_ROOT, GPAC_HARNESS) == "unknown"


# ---- crash bonus lambda -----------------------------------------------------

def test_lambda_zero_removes_the_bonus():
    configure_fitness("fixed", crash_bonus=0.0)
    s = _parse("library_crash.log")
    assert s.library_crash and s.total() < 1.0


# ---- normalisation ----------------------------------------------------------

def _ok(cov, ft, ex):
    return FitnessScores(coverage=cov, features=ft, exec_per_sec=ex, stability=1.0,
                         compile_ok=True, status=STATUS_OK)


SMOKE = [(9513, 24875, 4593), (9478, 24276, 4777), (9482, 24598, 4570), (9545, 24568, 4929)]  # ada-url smoke run


def test_fixed_mode_reproduces_the_saturation():
    totals = {round(_ok(*v).total(), 6) for v in SMOKE}
    assert totals == {1.0}   # 0.45 + 0.25 + 0.10 + 0.20*stability(1.0): every harness ties


@pytest.mark.parametrize("mode", ["pool_max", "rrf"])
def test_pool_modes_break_the_tie(mode):
    cfg = configure_fitness(mode)
    scores = [_ok(*v) for v in SMOKE]
    for s in scores:
        cfg.observe(s)
    totals = [s.total() for s in scores]
    assert len(set(round(t, 9) for t in totals)) == len(totals)          # no ties
    assert all(0.0 <= t <= 1.0 for t in totals)
    best_cov = max(range(len(SMOKE)), key=lambda i: SMOKE[i][0])
    assert totals[best_cov] > min(totals)


def test_pool_max_values():
    cfg = configure_fitness("pool_max")
    a, b = _ok(100, 10, 5.0), _ok(50, 20, 10.0)
    cfg.observe(a); cfg.observe(b)
    assert a.total() == pytest.approx(0.45 * 1 + 0.25 * 0.5 + 0.10 * 0.5 + 0.20)
    assert b.total() == pytest.approx(0.45 * 0.5 + 0.25 * 1 + 0.10 * 1 + 0.20)
    assert cfg.state()["max"] == {"coverage": 100.0, "features": 20.0, "exec_per_sec": 10.0}


def test_unmeasured_trials_do_not_enter_the_pool():
    cfg = configure_fitness("pool_max")
    cfg.observe(FitnessScores(status="NO_STATS", compile_ok=True))
    assert cfg.state()["n_observed"] == 0


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        configure_fitness("minmax")
