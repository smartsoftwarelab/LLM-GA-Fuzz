"""PATCH 5: mutation strategy chosen from the parent's fitness profile (paper Sec. III-E.1)."""
import random
from collections import Counter
from types import SimpleNamespace

import pytest

from agent.evo_gen import EvoISSTAFuzzer
from agent.modules.fitness import STATUS_OK, FitnessScores
from agent.modules.population import HarnessGenome
from agent.modules.variation import (LOW_STABILITY_STRATEGIES, MUTATION_STRATEGIES, PATH_PLATEAU_STRATEGIES,
                                     STRATEGY_NAMES, choose_strategy)


def _parent(stability=1.0, events=None):
    return FitnessScores(coverage=100, features=200, exec_per_sec=50.0, stability=stability,
                         compile_ok=True, status=STATUS_OK, crash_events=events or {})


def _draw(mode, parent, plateau, n=3000, seed=11):
    random.seed(seed)
    picks = [choose_strategy(mode, parent, plateau) for _ in range(n)]
    rules = {r for _, r in picks}
    share = lambda names: sum(1 for i, _ in picks if STRATEGY_NAMES[i] in names) / n  # noqa: E731
    return rules, share


def test_random_mode_reproduces_the_old_behaviour():
    random.seed(1234)
    old = [random.choice(MUTATION_STRATEGIES) for _ in range(200)]
    random.seed(1234)
    new = [MUTATION_STRATEGIES[choose_strategy("random", _parent(), True)[0]] for _ in range(200)]
    assert old == new


def test_rule_low_stability_fires_and_prioritises_safety_strategies():
    rules, share = _draw("profile", _parent(stability=0.5), plateau=False)
    assert rules == {"low_stability"}
    assert share(LOW_STABILITY_STRATEGIES) == pytest.approx(6 / 14, abs=0.04)   # 2 x weight 3 over 8 + 6


def test_crash_events_count_as_low_stability_even_if_trial_finished():
    rules, _ = _draw("profile", _parent(stability=1.0, events={"timeout": 2}), plateau=True, n=50)
    assert rules == {"low_stability"}    # rule 2 is checked before rule 1


def test_unmeasured_parent_counts_as_low_stability():
    rules, _ = _draw("profile", FitnessScores(status="NO_STATS", compile_ok=True), plateau=False, n=50)
    assert rules == {"low_stability"}


def test_rule_path_plateau_fires_and_prioritises_deeper_state_strategies():
    rules, share = _draw("profile", _parent(), plateau=True)
    assert rules == {"path_plateau"}
    assert share(PATH_PLATEAU_STRATEGIES) == pytest.approx(6 / 14, abs=0.04)


def test_otherwise_uniform():
    rules, share = _draw("profile", _parent(), plateau=False)
    assert rules == {"uniform"}
    assert share(PATH_PLATEAU_STRATEGIES) == pytest.approx(2 / 10, abs=0.04)


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        choose_strategy("bandit", _parent(), False)


def test_names_match_paper_table_ii():
    assert len(STRATEGY_NAMES) == 10 == len(set(STRATEGY_NAMES))
    assert set(LOW_STABILITY_STRATEGIES + PATH_PLATEAU_STRATEGIES) <= set(STRATEGY_NAMES)


@pytest.mark.parametrize("feats, expected", [
    ([100, 100, 100], True),
    ([90, 100, 100], False),
    ([100, 100], False),             # fewer than three generations
    ([None, None, None], False),     # nothing measured
])
def test_path_plateau_signal(feats, expected):
    fake = SimpleNamespace(generation_stats=[{"archive_max_features": f} for f in feats])
    assert EvoISSTAFuzzer._path_plateau(fake) is expected


def test_strategy_and_rule_are_recorded_on_the_child():
    g = HarnessGenome.make("int x;", 1, ["p"], "MUTATION")
    g.meta = {"strategy": "LOOPINJECTION", "strategy_rule": "path_plateau", "strategy_mode": "profile"}
    assert g.to_dict()["meta"]["strategy_rule"] == "path_plateau"
    assert Counter(STRATEGY_NAMES)["LOOPINJECTION"] == 1
