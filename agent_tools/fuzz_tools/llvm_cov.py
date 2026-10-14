"""Source-based coverage (llvm-cov) of a harness's final corpus.

Pipeline: rebuild the harness with OSS-Fuzz `--sanitizer=coverage`, replay each
corpus input once inside the project image (llvm_cov_replay.sh), merge the raw
profiles with llvm-profdata and export a summary with `llvm-cov export
-summary-only`. Only files under the library's source root are counted, and the
harness file itself is excluded.
"""
from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from agent_tools.fuzz_tools.compiler import Compiler
from agent_tools.fuzz_tools.coverage_result import CoverageResult, CoverageStatus
from constants import PROJECT_PATH, CompileResults, DockerResults, LanguageType
from utils.docker_utils import DockerUtils

METRICS = ("branches", "regions", "lines", "functions")
REPLAY_SCRIPT = "llvm_cov_replay.sh"
# Files copied from <out>/llmga_cov into the result's raw directory.
RAW_FILES = ("tool_versions.txt", "replay.tsv", "replay.log", "merge.log",
             "export.json", "export.err", "merged.profdata")


def library_scope_root(harness_path: str | Path, project_name: str) -> str:
    """Source-tree prefix of the target library, taken from the harness location.

    OSS-Fuzz checks the project out under /src/<repo>/ and benchmark harnesses
    live inside it (e.g. /src/cjson/fuzzing/x.c -> /src/cjson/). A harness placed
    directly in /src falls back to /src/<project_name>/.
    """
    parts = PurePosixPath(str(harness_path)).parts
    if len(parts) >= 4 and parts[0] == "/" and parts[1] == "src":
        return f"/src/{parts[2]}/"
    return f"/src/{project_name}/"


def scoped_summary(export: dict[str, Any], scope_root: str,
                   exclude: set[str]) -> tuple[dict[str, dict[str, int]], list[str], set[str]]:
    """Sum llvm-cov per-file summaries over files under scope_root, minus `exclude`.

    Returns (totals per metric, files counted, metrics present in at least one file).
    """
    totals = {m: {"covered": 0, "count": 0} for m in METRICS}
    files: list[str] = []
    present: set[str] = set()
    for unit in export["data"]:
        for entry in unit["files"]:
            name = entry["filename"]
            if not name.startswith(scope_root) or name in exclude:
                continue
            files.append(name)
            summary = entry["summary"]
            for m in METRICS:
                if m in summary:
                    present.add(m)
                    totals[m]["covered"] += int(summary[m]["covered"])
                    totals[m]["count"] += int(summary[m]["count"])
    return totals, sorted(files), present


def result_from_export(export: Any, scope_root: str, exclude: set[str], metric: str,
                       **extra: Any) -> CoverageResult:
    """Turn a parsed `llvm-cov export -summary-only` document into a CoverageResult."""
    def failed(msg: str) -> CoverageResult:
        return CoverageResult(CoverageStatus.PARSE_FAILED, metric, error_message=msg,
                              scope_root=scope_root, **extra)

    try:
        totals, files, present = scoped_summary(export, scope_root, exclude)
        whole = {m: {"covered": int(v["covered"]), "count": int(v["count"])}
                 for m, v in export["data"][0].get("totals", {}).items() if m in METRICS}
    except (KeyError, IndexError, TypeError, ValueError) as e:
        return failed(f"malformed llvm-cov export: {type(e).__name__}: {e}")

    if not files:
        return failed(f"no source files under scope_root {scope_root}")
    if metric not in present:
        return failed(f"metric '{metric}' not present in llvm-cov export")
    if totals[metric]["count"] == 0:
        return failed(f"metric '{metric}' has zero instrumented units under {scope_root}")

    covered, total = totals[metric]["covered"], totals[metric]["count"]
    status = CoverageStatus.OK if covered > 0 else CoverageStatus.NO_COVERAGE
    return CoverageResult(status, metric, covered=covered, total=total, scope_root=scope_root,
                          metrics={"scope": totals, "whole_binary": whole, "files_in_scope": files},
                          **extra)


def parse_replay_tsv(path: Path) -> tuple[int, int]:
    """(inputs replayed, inputs with non-zero exit) from replay.tsv."""
    replayed = failed = 0
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        replayed += 1
        if line.rsplit("\t", 1)[-1].strip() != "0":
            failed += 1
    return replayed, failed


class LlvmCovCollector:

    def __init__(self, oss_fuzz_dir: Path, benchmark_dir: Path, project_name: str, new_project_name: str,
                 project_lang: LanguageType, raw_dir: Path, metric: str = "branches",
                 input_timeout: int = 25, total_timeout: int = 3600,
                 include_path: Optional[set[str]] = None, logger: Optional[logging.Logger] = None) -> None:
        if metric not in METRICS:
            raise ValueError(f"unknown coverage metric {metric!r}; expected one of {METRICS}")
        self.oss_fuzz_dir = Path(oss_fuzz_dir)
        self.benchmark_dir = Path(benchmark_dir)
        self.project_name = project_name
        self.new_project_name = new_project_name
        self.project_lang = project_lang
        self.raw_dir = Path(raw_dir)
        self.metric = metric
        self.input_timeout = input_timeout
        self.total_timeout = total_timeout
        self.include_path = include_path
        self.logger = logger

    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger.info(msg)

    def collect(self, harness_code: str, harness_path: Path, fuzzer_name: str, corpus_dir: Path) -> CoverageResult:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        scope_root = library_scope_root(harness_path, self.project_name)
        base: dict[str, Any] = {"raw_output_path": str(self.raw_dir), "scope_root": scope_root}

        corpus_dir = Path(corpus_dir).resolve()
        inputs = sorted(p for p in corpus_dir.iterdir() if p.is_file()) if corpus_dir.is_dir() else []
        if not inputs:
            return CoverageResult(CoverageStatus.EMPTY_CORPUS, self.metric,
                                  error_message=f"no inputs in {corpus_dir}", inputs_replayed=0, **base)

        # 1. coverage build of the same harness
        compiler = Compiler(self.oss_fuzz_dir, self.benchmark_dir, self.project_name, self.new_project_name,
                            self.include_path, sanitizer="coverage")
        compile_res, build_msg = compiler.compile_harness(harness_code, harness_path, fuzzer_name)
        (self.raw_dir / "coverage_build.log").write_text(build_msg or "", errors="replace")
        if compile_res != CompileResults.Success:
            return CoverageResult(CoverageStatus.BUILD_FAILED, self.metric,
                                  error_message=f"coverage build failed: {compile_res.value}", **base)

        # 2. replay + merge + export inside the project image
        local_out = self.oss_fuzz_dir / "build" / "out" / self.new_project_name
        shutil.copy(Path(PROJECT_PATH) / "agent_tools" / "fuzz_tools" / REPLAY_SCRIPT, local_out / REPLAY_SCRIPT)
        docker = DockerUtils(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang)
        volumes = {str(local_out): {"bind": "/out", "mode": "rw"},
                   str(corpus_dir): {"bind": "/corpus", "mode": "ro"}}
        self._log(f"llvm-cov replay of {len(inputs)} inputs for {fuzzer_name}")
        t0 = time.monotonic()
        msg = docker.run_cmd(["bash", f"/out/{REPLAY_SCRIPT}", fuzzer_name, str(self.input_timeout)],
                             timeout=self.total_timeout, volumes=volumes, working_dir="/out")
        elapsed = time.monotonic() - t0
        (self.raw_dir / "replay_stdout.txt").write_text(msg, errors="replace")
        for name in RAW_FILES:
            src = local_out / "llmga_cov" / name
            if src.exists():
                shutil.copy(src, self.raw_dir / name)

        replayed = failed = None
        if (self.raw_dir / "replay.tsv").exists():
            replayed, failed = parse_replay_tsv(self.raw_dir / "replay.tsv")
        base.update(inputs_replayed=replayed, inputs_failed=failed)

        if msg.startswith(DockerResults.Error.value):
            status = CoverageStatus.TIMEOUT if elapsed >= self.total_timeout else CoverageStatus.TOOL_FAILED
            return CoverageResult(status, self.metric, error_message=msg.strip()[-500:], **base)
        if "LLMGA_COV_DONE" not in msg:
            marker = next((ln for ln in msg.splitlines() if "LLMGA_COV_ERROR" in ln), msg.strip()[-500:])
            return CoverageResult(CoverageStatus.TOOL_FAILED, self.metric, error_message=marker, **base)

        # 3. parse
        try:
            export = json.loads((self.raw_dir / "export.json").read_text())
        except (OSError, json.JSONDecodeError) as e:
            return CoverageResult(CoverageStatus.PARSE_FAILED, self.metric,
                                  error_message=f"cannot read export.json: {e}", **base)
        return result_from_export(export, scope_root, {str(harness_path)}, self.metric,
                                  raw_output_path=base["raw_output_path"],
                                  inputs_replayed=replayed, inputs_failed=failed)
