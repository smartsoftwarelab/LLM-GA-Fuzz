"""PATCH 7: analysis statistics."""
import pytest

from utils.analysis import a12, hier_bootstrap_median, median_iqr, recompute_totals, rel_improvement


def test_a12_definition():
    assert a12([3, 4], [1, 2]) == 1.0
    assert a12([1, 2], [3, 4]) == 0.0
    assert a12([1, 2], [1, 2]) == 0.5
    assert a12([], [1]) is None


def test_rel_improvement_undefined_for_zero_baseline():
    assert rel_improvement(100, 120) == pytest.approx(0.2)
    assert rel_improvement(139, 109) == pytest.approx(-30 / 139)
    assert rel_improvement(0, 5) is None and rel_improvement(None, 5) is None


def test_hier_bootstrap_is_seeded_and_brackets_the_point():
    data = {"a": [0.1, 0.2, 0.3], "b": [-0.1, 0.0, 0.1], "c": [0.4, 0.5, 0.6]}
    p1 = hier_bootstrap_median(data, n_boot=2000, seed=1)
    p2 = hier_bootstrap_median(data, n_boot=2000, seed=1)
    assert p1 == p2 and p1[1] <= p1[0] <= p1[2] and p1[0] == pytest.approx(0.2)
    assert hier_bootstrap_median({}) == (None, None, None)


def test_median_iqr():
    assert median_iqr([1, 2, 3, 4, 5]) == (3.0, 2.0, 4.0)


CFG = {"normalization": "pool_max", "crash_bonus_lambda": 0.6,
       "W_COVERAGE": 0.45, "W_FEATURES": 0.25, "W_EXEC": 0.10, "W_STABILITY": 0.20}


def _g(cov, ft, ex, crash, ok=True, status="OK"):
    return {"compile_ok": ok, "fitness": {"status": status, "coverage": cov, "features": ft,
                                          "exec_per_sec": ex, "stability": 1.0, "library_crash": crash, "total": 0}}


def test_recompute_totals_pool_max_and_bonus():
    gs = {"crasher": _g(50, 10, 5, True), "coverer": _g(100, 20, 10, False)}
    t = recompute_totals(gs, CFG)
    assert t["coverer"] == (pytest.approx(1.0), pytest.approx(1.0))
    assert t["crasher"][1] == pytest.approx(0.45 * 0.5 + 0.25 * 0.5 + 0.10 * 0.5 + 0.20)
    assert t["crasher"][0] == pytest.approx(t["crasher"][1] + 0.6)
    top_with = max(t, key=lambda k: t[k][0])
    top_wo = max(t, key=lambda k: t[k][1])
    assert (top_with, top_wo) == ("crasher", "coverer")       # the bonus changes the top genome


def test_recompute_ignores_uncompiled_and_unmeasured():
    gs = {"a": _g(10, 1, 1, False), "b": _g(None, None, None, False, status="NO_STATS"), "c": _g(99, 9, 9, False, ok=False)}
    t = recompute_totals(gs, CFG)
    assert set(t) == {"a", "b"} and t["b"] == (0.0, 0.0)
