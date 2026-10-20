"""PATCH 8: near-init crashes in fork mode are harness failures; campaign disk hygiene.

fork_always_crash.log is an excerpt of the 5-minute evaluation log of coturn rep4 final_best
(campaign 2026-10-18): 4487 executed units in 4487 fork jobs, a SEGV in every job, and still
"INFO: exiting:". fork_rare_crash.log is constructed (900 units, 40 jobs, one crash).
Fork status line "#N: ... job: J": N = executed units of finished jobs (libFuzzer FuzzerFork.cpp,
NumRuns += number_of_executed_units), J = id of the job that just finished.
"""
import json
from pathlib import Path

import pytest

from agent.modules import fitness as F
from agent.modules.fitness import FitnessConfig, configure_fitness, extract_coverage_from_log
from utils.campaign import cleanup_run_workspace, first_initial_error, free_gb

FIX = Path(__file__).parent / "fixtures"
ROOT, HARNESS = "/src/coturn/", "/src/coturn/fuzzing/FuzzStun.c"


@pytest.fixture(autouse=True)
def _fresh_config():
    configure_fitness("fixed")
    yield
    configure_fitness("fixed")


def _parse(name, sub="p08"):
    return extract_coverage_from_log(FIX / sub / name, scope_root=ROOT, harness_path=HARNESS)


def test_crash_on_every_input_is_a_harness_failure_without_bonus():
    s = _parse("fork_always_crash.log")
    assert s.execs_per_job == pytest.approx(1.0)
    assert s.near_init_crash and s.stability == 0.0
    assert s.discard_reason == "harness_failure:near_init_crash"
    s.apply_crash_location("library")             # even if a reproduced stack lies in the library
    assert s.library_crash is False and s.discard_reason == "harness_failure:near_init_crash"
    assert s.total() == pytest.approx(F.W_COVERAGE * 196 / F.NORM_COVERAGE + F.W_FEATURES * 291 / F.NORM_FEATURES)


def test_patch4_rules_rewarded_the_same_trial():
    configure_fitness("fixed", near_init_execs=None)
    s = _parse("fork_always_crash.log")
    s.apply_crash_location("library")
    assert s.stability == 1.0 and s.library_crash is True and not s.near_init_crash
    assert s.total() > F.CRASH_BONUS + F.W_STABILITY      # bonus + full stability for a broken harness


def test_crash_after_real_fuzzing_keeps_the_bonus():
    s = _parse("fork_rare_crash.log")
    assert s.execs_per_job == pytest.approx(900 / 40) and not s.near_init_crash and s.stability == 1.0
    s.apply_crash_location("library")
    assert s.library_crash is True and s.discard_reason is None


def test_frequent_job_crashes_with_many_executions_are_not_near_init():
    s = _parse("fork_ok.log", "p02")                 # ada-url: crash counter 9 after 10 jobs, 2.39M units
    assert s.execs_per_job == pytest.approx(2393153 / 10) and not s.near_init_crash and s.stability == 1.0


def test_non_fork_logs_are_unchanged():
    new = _parse("library_crash.log", "p04")
    configure_fitness("fixed", near_init_execs=None)
    old = _parse("library_crash.log", "p04")
    assert new.execs_per_job is None and not new.near_init_crash
    assert (new.stability, new.library_crash, new.discard_reason) == (old.stability, old.library_crash, old.discard_reason)


def test_config_state_records_the_threshold():
    assert configure_fitness("pool_max").state()["near_init_execs_per_job"] == 3.0
    assert FitnessConfig("fixed", near_init_execs=None).state()["near_init_execs_per_job"] is None


def test_cleanup_removes_only_the_run_copy(tmp_path):
    name = "run1_abcdefghijklmnop"
    for sub in ("projects", "build/out", "build/work"):
        (tmp_path / sub / name).mkdir(parents=True)
        (tmp_path / sub / "coturn").mkdir(parents=True, exist_ok=True)
    removed = cleanup_run_workspace(tmp_path, name, remove_image=False)
    assert len(removed) == 3
    assert not any((tmp_path / sub / name).exists() for sub in ("projects", "build/out", "build/work"))
    assert all((tmp_path / sub / "coturn").exists() for sub in ("projects", "build/out", "build/work"))
    with pytest.raises(ValueError):
        cleanup_run_workspace(tmp_path, "coturn", remove_image=False)


def test_free_gb_and_first_initial_error(tmp_path):
    assert free_gb([tmp_path]) > 0 and free_gb([tmp_path / "missing"]) is None
    (tmp_path / "run_manifest.json").write_text(json.dumps({"initial_attempts": [
        {"index": 1, "status": "EXCEPTION", "error": "AssertionError: Failed to build the docker image for run1_x"},
        {"index": 2, "status": "EXCEPTION", "error": "other"}]}))
    assert first_initial_error(tmp_path).startswith("AssertionError: Failed to build")
    assert first_initial_error(None) is None
