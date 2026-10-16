"""PATCH 3b: base images are not pulled during a run unless configured; build timings are recorded."""
import json

import pytest

from agent_tools.fuzz_tools.compiler import record_build_timing
from bench_cfg import BenchConfig
from constants import CompileResults
from utils.oss_fuzz_utils import OSSFuzzUtils

FAKE_KEY = "sk-" + "test" + "x" * 40


def _cfg(tmp_path, extra=""):
    p = tmp_path / "cfg.yaml"
    p.write_text(f"save_root: {tmp_path / 'out'}\n{extra}")
    return str(p)


def _build_image_cmd(tmp_path):
    proj = tmp_path / "oss-fuzz" / "projects" / "demo"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "project.yaml").write_text("language: c\n")
    return OSSFuzzUtils(tmp_path / "oss-fuzz", tmp_path, "demo", "demo_run").get_script_cmd("build_image")


@pytest.mark.parametrize("extra, flag", [("", "--no-pull"),
                                         ("oss_fuzz_pull_images: false\n", "--no-pull"),
                                         ("oss_fuzz_pull_images: true\n", "--pull")])
def test_pull_flag_follows_config(tmp_path, monkeypatch, extra, flag):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.delenv("LLMGA_OSSFUZZ_PULL", raising=False)
    cfg = BenchConfig(_cfg(tmp_path, extra))
    cmd = _build_image_cmd(tmp_path)
    assert flag in cmd and ({"--pull", "--no-pull"} - {flag}).isdisjoint(cmd)
    assert cfg.snapshot_dict()["oss_fuzz_pull_images"] is (flag == "--pull")


def test_without_benchconfig_previous_behaviour_is_kept(tmp_path, monkeypatch):
    monkeypatch.delenv("LLMGA_OSSFUZZ_PULL", raising=False)
    assert "--pull" in _build_image_cmd(tmp_path)


def test_build_timing_written_only_when_enabled(tmp_path, monkeypatch):
    log = tmp_path / "timings.jsonl"
    monkeypatch.delenv("LLMGA_BUILD_TIMINGS", raising=False)
    record_build_timing("p", None, 1.0, 3.0, CompileResults.Success)
    assert not log.exists()
    monkeypatch.setenv("LLMGA_BUILD_TIMINGS", str(log))
    record_build_timing("p", "coverage", 100.04, 160.0, CompileResults.Success)
    record_build_timing("p", None, None, 5.0, CompileResults.ImageError)
    a, b = [json.loads(x) for x in log.read_text().splitlines()]
    assert (a["build_image_s"], a["build_fuzzers_s"], a["total_s"], a["sanitizer"]) == (100.0, 60.0, 160.0, "coverage")
    assert (b["build_image_s"], b["build_fuzzers_s"], b["result"]) == (None, None, "ImageError")
