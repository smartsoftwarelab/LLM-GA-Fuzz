"""PATCH 6: campaign sampling and bookkeeping."""
import json
from pathlib import Path

from utils.campaign import (count_http_posts, files_with_secrets, load_benchmark, pick_final_best,
                            pick_gen0_best, rep_seed, run_fuzzer_info, stratified_order)

BENCH = Path(__file__).resolve().parent.parent / "benchmark-sets" / "function_0"


def test_benchmark_has_243_targets_66_c_177_cpp():
    targets = load_benchmark(BENCH)
    assert len(targets) == 243
    langs = [t["language"] for t in targets]
    assert (langs.count("c"), langs.count("c++")) == (66, 177)


def test_stratified_order_is_seeded_and_proportional():
    targets = load_benchmark(BENCH)
    a, b, c = (stratified_order(targets, s, 12) for s in (20261016, 20261016, 7))
    assert a["quota"] == {"c": 3, "c++": 9}
    assert a["order"] == b["order"] and a["order"] != c["order"]
    assert sorted(t["project"] for t in a["order"]["c"]) == sorted(t["project"] for t in targets if t["language"] == "c")


def test_rep_seeds_differ():
    assert len({rep_seed(20261016, r) for r in range(1, 6)}) == 5


def _genome(path, gid, gen, total, code="int x;", ok=True):
    path.write_text(json.dumps({"genome_id": gid, "generation": gen, "code": code, "compile_ok": ok,
                                "fitness": {"total": total}}))


def test_pick_gen0_and_final_best(tmp_path):
    g0 = tmp_path / "evolution" / "gen_000"
    g0.mkdir(parents=True)
    _genome(g0 / "00_a.json", "a", 0, 0.7)
    _genome(g0 / "01_b.json", "b", 0, 0.9)
    _genome(g0 / "02_c.json", "c", 0, 1.5, ok=False)        # not compiled: never the baseline
    fin = tmp_path / "evolution" / "final"
    fin.mkdir(parents=True)
    _genome(fin / "best_01_d.json", "d", 3, 0.95)
    assert pick_gen0_best(tmp_path)["genome_id"] == "b"
    assert pick_final_best(tmp_path)["genome_id"] == "d"


def test_http_posts_and_secret_scan(tmp_path):
    audit = tmp_path / "a.log"
    audit.write_text('x HTTP Request: POST https://api.openai.com/v1/chat/completions "HTTP/1.1 200 OK"\nother\n' * 3)
    assert count_http_posts(audit) == 3 and count_http_posts(tmp_path / "missing.log") is None
    (tmp_path / "clean.txt").write_text("sk-ssh-ed25519-cert-v01@openssh.com")      # OpenSSH key type, not a secret
    assert files_with_secrets(tmp_path) == []
    (tmp_path / "leak.txt").write_text("key=" + "sk-" + "proj-" + "A" * 40)
    assert files_with_secrets(tmp_path) == [str(tmp_path / "leak.txt")]


def test_run_fuzzer_info_falls_back_to_benchmark_target(tmp_path):
    """PATCH 10: v2 coturn rep2 had no validated initial harness, so no fuzzer_info.json."""
    info, src = run_fuzzer_info(tmp_path, BENCH, "coturn")
    assert src == "benchmark_yaml" and info == {"fuzzer_name": "FuzzStun", "fuzzer_path": "/src/coturn/fuzzing/FuzzStun.c"}
    (tmp_path / "run1_abcdefghijklmnop").mkdir()
    (tmp_path / "run1_abcdefghijklmnop" / "fuzzer_info.json").write_text(json.dumps({"fuzzer_name": "x", "fuzzer_path": "/src/y.c"}))
    assert run_fuzzer_info(tmp_path, BENCH, "coturn") == ({"fuzzer_name": "x", "fuzzer_path": "/src/y.c"}, "validated_initial_harness")
    assert run_fuzzer_info(tmp_path / "none", BENCH, "no_such_project") == (None, "missing")
