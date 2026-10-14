"""PATCH 2 acceptance driver: run LlvmCovCollector on the llmga-covref project.

Called by scripts/p02_coverage_reference.sh; needs Docker and the oss-fuzz checkout.
"""
import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from agent_tools.fuzz_tools.llvm_cov import LlvmCovCollector  # noqa: E402
from constants import LanguageType  # noqa: E402

PROJECT = "llmga-covref"
HARNESS_IN_IMAGE = Path(f"/src/{PROJECT}/fuzz_tinylib.c")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oss-fuzz-dir", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--metric", default="branches")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    collector = LlvmCovCollector(
        oss_fuzz_dir=Path(args.oss_fuzz_dir),
        benchmark_dir=REPO / "benchmark-sets" / "function_0",
        project_name=PROJECT,
        new_project_name=PROJECT,
        project_lang=LanguageType.C,
        raw_dir=out / "raw",
        metric=args.metric,
        input_timeout=25,
        total_timeout=1800,
    )
    harness = (REPO / "tests" / "fixtures" / "p02" / "covref" / "fuzz_tinylib.c").read_text()
    result = collector.collect(harness, HARNESS_IN_IMAGE, "fuzz_tinylib", Path(args.corpus))
    (out / "result.json").write_text(json.dumps(result.to_dict(), indent=2))
    scope = result.metrics.get("scope", {})
    fn = scope.get("functions", {})
    print(f"{out.name}: status={result.status.value} {result.metric}={result.covered}/{result.total} "
          f"functions={fn.get('covered')}/{fn.get('count')} files={result.metrics.get('files_in_scope')} "
          f"inputs={result.inputs_replayed} failed={result.inputs_failed} err={result.error_message}")


if __name__ == "__main__":
    main()
