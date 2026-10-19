"""PATCH 7: analysis statistics."""
import pytest

from utils.analysis import _bonus_changed_top, a12, hier_bootstrap_median, median_iqr, rel_improvement


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


def test_bonus_changed_top():
    g = lambda gid, tot, crash: {"genome_id": gid, "compile_ok": True,  # noqa: E731
                                 "fitness": {"total": tot, "library_crash": crash}}
    assert _bonus_changed_top({"a": g("a", 1.5, True), "b": g("b", 0.95, False)}, 0.6) is True   # 0.9 < 0.95
    assert _bonus_changed_top({"a": g("a", 1.7, True), "b": g("b", 0.95, False)}, 0.6) is False  # 1.1 > 0.95
    assert _bonus_changed_top({"a": g("a", 0.9, False)}, 0.0) is False
