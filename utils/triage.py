import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


logger = logging.getLogger(__name__)


UNKNOWN_STRING = "Unknown"
TIMEOUT_STRING = "Timeout"
OOM_STRING = "Out of memory"
PADDING_STRING = "Padding"


class SanitizerType(Enum):
    ASAN = "address"
    UBSAN = "undefined"
    MSAN = "memory"
    JAZZER = "address"
    UNKNOWN = "none"


@dataclass
class CrashInfo:
    bug_type: str
    trigger_point: str
    summary: str
    harness_name: str
    poc: str
    sanitizer: str
    sarif_report: Dict[str, Any]
    raw_output: str = ""
    dup_token: str = ""
    target_reached: bool = False
    covered_functions: List[str] = None

    def __post_init__(self):
        if self.covered_functions is None:
            self.covered_functions = []


class CrashTriager:
    def __init__(self, oss_fuzz_path: Optional[Path] = None):
        """Crash log triager and deduper.

        Args:
            oss_fuzz_path: Optional path to the OSS-Fuzz checkout for reproduction mode.
        """
        self.oss_fuzz_path = oss_fuzz_path
        self.jazzer_pattern = re.compile(
            r"==\s*Java Exception:\s*(com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssue\w+):\s*(.*?)(?=\n|$)"
        )
        self.c_bug_type_pattern = re.compile(
            r"SUMMARY:\s*(AddressSanitizer|UndefinedBehaviorSanitizer):\s*(.*?)(?=\s+|$)"
        )
        self.c_location_pattern = re.compile(
            r"SUMMARY:.*?(?:[\w/\-\.]+\.(?:c|cc|cpp|h|hpp)):(\d+)(?::\d+)?\s+(?:in\s+(.+))?"
        )
        self.stack_trace_pattern = re.compile(r"\s*#\d+\s")
        self.dedup_token_pattern = re.compile(r"DEDUP_TOKEN:\s*([^\n]+)")
        self.timeout_pattern = re.compile(r"==\d*==\s*ERROR:\s*libFuzzer: timeout after\s\d+\sseconds")
        self.timeout_kwd = "SUMMARY: libFuzzer: timeout"
        self.covered_func_pattern = re.compile(r"COVERED_FUNC:\s*hits:\s*(\d+)\s*edges:\s*\d+/\d+\s*(.+?)\s+")
        self.uncovered_func_pattern = re.compile(r"UNCOVERED_FUNC:.*?(?=\n|$)", re.MULTILINE)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    async def cleanup(self):
        logger.debug("Cleaning up CrashTriager resources")

    def extract_dedup_token(self, output: str) -> str:
        if match := self.dedup_token_pattern.search(output):
            return match.group(1)
        return UNKNOWN_STRING

    def format_summary_lines(self, output: str, max_lines: int = 5) -> str:
        summary_lines = []
        for line in output.splitlines():
            if self.stack_trace_pattern.match(line):
                parts = line.split(" in ", 1)
                summary_lines.append(parts[1].strip() if len(parts) > 1 else line.strip())
        return "\n".join(summary_lines[:max_lines])

    def _try_decode(self, data: bytes) -> str:
        encodings = ["utf-8", "latin1", "ascii"]
        for encoding in encodings:
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                logger.debug(f"Failed to decode with {encoding}")
        raise UnicodeDecodeError("Failed to decode with all encodings")

    def _detect_sanitizer(self, output: str) -> SanitizerType:
        if "Java Exception:" in output:
            return SanitizerType.JAZZER
        if "AddressSanitizer" in output:
            return SanitizerType.ASAN
        if "UndefinedBehaviorSanitizer" in output:
            return SanitizerType.UBSAN
        return SanitizerType.UNKNOWN

    def _extract_java_location(self, output: str) -> str:
        for line in output.splitlines():
            if "at " in line and ".java:" in line:
                return line.strip().replace("\tat ", "")
        return UNKNOWN_STRING

    def _extract_bug_info(self, output: str, sanitizer: SanitizerType) -> tuple[str, str]:
        if self.timeout_pattern.search(output) or self.timeout_kwd in output:
            return TIMEOUT_STRING, UNKNOWN_STRING

        if sanitizer == SanitizerType.JAZZER:
            match = self.jazzer_pattern.search(output)
            if match:
                severity = match.group(1).replace("com.code_intelligence.jazzer.api.", "")
                description = match.group(2).strip()
                return f"{severity}: {description}", self._extract_java_location(output)

        bug_match = self.c_bug_type_pattern.search(output)
        loc_match = self.c_location_pattern.search(output)
        if bug_match:
            bug_type = f"{bug_match.group(1)}: {bug_match.group(2)}"
            trigger_point = loc_match.group(0).replace("SUMMARY: ", "", 1) if loc_match else UNKNOWN_STRING
            return bug_type, trigger_point

        return UNKNOWN_STRING, UNKNOWN_STRING

    def extract_timeout_info(self, output: str) -> Optional[str]:
        timeout_detail_pattern = re.compile(r"libFuzzer: timeout after (\d+) seconds")
        if match := timeout_detail_pattern.search(output):
            return f"libFuzzer: timeout after {match.group(1)} seconds"
        if self.timeout_pattern.search(output) or self.timeout_kwd in output:
            return "libFuzzer: timeout"
        return None

    def extract_thread_info(self, output: str) -> list[dict]:
        thread_info: list[dict] = []
        if "Stack traces of all JVM threads:" not in output:
            return thread_info

        thread_pattern = re.compile(r"Thread\[([^,]+),(\d+),([^\]]+)\]")
        for match in thread_pattern.finditer(output):
            thread_name = match.group(1)
            thread_priority = int(match.group(2))
            thread_group = match.group(3)
            start_pos = match.end()
            next_thread = thread_pattern.search(output, start_pos)
            end_pos = next_thread.start() if next_thread else len(output)
            stack_trace_text = output[start_pos:end_pos].strip()
            stack_trace_lines = [line.strip() for line in stack_trace_text.split("\n") if line.strip()]
            thread_info.append(
                {
                    "name": thread_name,
                    "priority": thread_priority,
                    "group": thread_group,
                    "stack_trace": stack_trace_lines,
                }
            )
        return thread_info

    def extract_covered_functions(self, output: str) -> List[str]:
        """Extract function names from COVERED_FUNC lines with hits > 0, excluding std/gnu functions."""
        covered = []
        for match in self.covered_func_pattern.finditer(output):
            hits = int(match.group(1))
            func_name = match.group(2).strip()
            # Filter out standard library and GNU functions immediately
            if hits > 0 and not self._is_std_lib_function(func_name):
                covered.append(func_name)
        return covered

    def _is_std_lib_function(self, func_name: str) -> bool:
        """Check if function name is from standard library or GNU runtime."""
        return "std::" in func_name or "__gnu_cxx::" in func_name

    def _filter_uncovered_std_funcs(self, output: str) -> str:
        """Remove UNCOVERED_FUNC lines for std/gnu functions from output."""
        lines = []
        for line in output.splitlines():
            # Skip UNCOVERED_FUNC lines containing std:: or __gnu_cxx::
            if line.startswith("UNCOVERED_FUNC:") and ("std::" in line or "__gnu_cxx::" in line):
                continue
            lines.append(line)
        return "\n".join(lines)

    def check_target_reached(self, output: str, target_function: str) -> bool:
        """Check if target function appears in COVERED_FUNC lines with hits > 0."""
        if not target_function:
            return False
        covered = self.extract_covered_functions(output)
        for func in covered:
            if target_function in func:
                return True
        return False

    def _parse_output(
        self, output: str, harness_name: str, poc: Path, target_function: Optional[str] = None
    ) -> Optional[CrashInfo]:
        if not output:
            logger.error("Crash output is empty; skipping")
            return None

        sanitizer = self._detect_sanitizer(output)
        bug_type, trigger_point = self._extract_bug_info(output, sanitizer)
        summary = self.extract_timeout_info(output) or self.format_summary_lines(output)
        dup_token = self.extract_dedup_token(output).rstrip()
        covered_functions = self.extract_covered_functions(output)
        target_reached = self.check_target_reached(output, target_function) if target_function else False

        # Filter out UNCOVERED_FUNC lines for std/gnu functions from raw output
        filtered_output = self._filter_uncovered_std_funcs(output)

        return CrashInfo(
            bug_type=bug_type,
            trigger_point=trigger_point,
            summary=summary,
            raw_output=filtered_output,
            sanitizer=sanitizer.value,
            harness_name=harness_name,
            poc=str(poc),
            dup_token=dup_token,
            sarif_report={"version": "2.1.0", "runs": []},
            target_reached=target_reached,
            covered_functions=covered_functions,
        )

    def compute_dedup_key(self, crash: CrashInfo) -> str:
        if crash.dup_token and crash.dup_token != UNKNOWN_STRING:
            return crash.dup_token

        head = crash.summary.split("\n", 1)[0] if crash.summary else ""
        basis = f"{crash.bug_type}|{crash.trigger_point}|{head}"
        return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]

    async def triage_crash(self, project_name: str, fuzzer_name: str, crash_file: Path) -> Optional[CrashInfo]:
        if not self.oss_fuzz_path:
            raise ValueError("oss_fuzz_path is required for reproduction mode")

        cmd = [
            "python3",
            "infra/helper.py",
            "reproduce",
            project_name,
            fuzzer_name,
            str(crash_file),
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=self.oss_fuzz_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        try:
            output = self._try_decode(stdout + stderr)
        except UnicodeDecodeError as exc:
            logger.error(f"Failed to decode process output: {exc}")
            return None

        if process.returncode == 0:
            logger.error("Crash reproduction did not crash; skipping")
            return None

        if process.returncode == 70 or "ERROR: libFuzzer: timeout after" in output:
            thread_info = self.extract_thread_info(output)
            timeout_dup_token = (
                thread_info[0]["name"] + str(thread_info[0]["priority"]) + str(thread_info[0]["group"])
                if thread_info
                else UNKNOWN_STRING
            )
            return CrashInfo(
                bug_type=TIMEOUT_STRING,
                trigger_point=thread_info[0]["name"] if thread_info else UNKNOWN_STRING,
                summary=self.extract_timeout_info(output) or UNKNOWN_STRING,
                raw_output=output,
                sanitizer=SanitizerType.UNKNOWN.value,
                harness_name=fuzzer_name,
                poc=str(crash_file),
                dup_token=timeout_dup_token,
                sarif_report={"version": "2.1.0", "runs": []},
            )

        return self._parse_output(output, harness_name=fuzzer_name, poc=crash_file)

    async def reproduce_with_binary(
        self,
        binary: Path,
        crash_file: Path,
        target_function: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        docker_image: Optional[str] = None,
        print_coverage: bool = True,
    ) -> Optional[CrashInfo]:
        """Reproduce a crash using a binary directly or inside Docker.

        Args:
            binary: Path to the fuzzer binary.
            crash_file: Path to the crash sample.
            target_function: Optional target function to check in coverage.
            env_vars: Optional environment variables to set.
            docker_image: Optional Docker image name to run reproduction inside.
            print_coverage: Whether to add -print_coverage=1 flag.

        Returns:
            CrashInfo if crash was reproduced, None otherwise.
        """
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        if docker_image:
            cmd = await self._build_docker_command(
                binary, crash_file, env_vars, docker_image, print_coverage
            )
            cwd = None
        else:
            binary_abs = binary.resolve()
            crash_abs = crash_file.resolve()
            cwd = binary_abs.parent
            cmd = [f"./{binary_abs.name}", str(crash_abs)]
            if print_coverage:
                cmd.insert(1, "-print_coverage=1")

        logger.debug(f"Running command: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env if not docker_image else None,
        )
        stdout, stderr = await process.communicate()

        try:
            output = self._try_decode(stdout + stderr)
        except UnicodeDecodeError as exc:
            logger.error(f"Failed to decode process output: {exc}")
            return None

        # Check if it actually crashed
        has_crash = (
            process.returncode != 0
            or "ERROR:" in output
            or "SUMMARY:" in output
            or "Sanitizer" in output
        )

        if not has_crash:
            logger.warning(f"No crash detected for {crash_file}")
            return None

        harness_name = binary.stem
        return self._parse_output(output, harness_name, crash_file, target_function)

    async def _build_docker_command(
        self,
        binary: Path,
        crash_file: Path,
        env_vars: Optional[Dict[str, str]],
        docker_image: str,
        print_coverage: bool,
    ) -> List[str]:
        """Build Docker run command for crash reproduction."""
        binary_dir = binary.parent.resolve()
        binary_name = binary.name
        crash_file_resolved = crash_file.resolve()

        # Determine if crash file is inside binary dir or needs separate mount
        try:
            crash_relative = crash_file_resolved.relative_to(binary_dir)
            crash_in_binary_dir = True
        except ValueError:
            crash_in_binary_dir = False

        cmd = ["docker", "run", "--rm"]

        # Mount binary directory
        cmd.extend(["-v", f"{binary_dir}:/out"])
        cmd.extend(["-w", "/out"])

        # Mount crash file if not in binary directory
        if not crash_in_binary_dir:
            crash_dir = crash_file_resolved.parent
            cmd.extend(["-v", f"{crash_dir}:/crashes"])
            crash_path_in_container = f"/crashes/{crash_file_resolved.name}"
        else:
            crash_path_in_container = f"/out/{crash_relative}"

        # Add environment variables
        if env_vars:
            for key, value in env_vars.items():
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(docker_image)

        # Build the actual command to run inside container
        inner_cmd = f"./{binary_name}"
        if print_coverage:
            inner_cmd += " -print_coverage=1"
        inner_cmd += f" {crash_path_in_container}"

        cmd.extend(["bash", "-c", inner_cmd])

        return cmd

    async def triage_crash_log(
        self, logfile: Path, harness_name: str, target_function: Optional[str] = None
    ) -> Optional[CrashInfo]:
        try:
            output = logfile.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.error(f"Failed to read log {logfile}: {exc}")
            return None

        return self._parse_output(output, harness_name=harness_name, poc=logfile, target_function=target_function)


def iter_input_files(root: Path, patterns: list[str], recursive: bool = True) -> list[Path]:
    files: set[Path] = set()
    if root.is_file():
        return [root]

    for pattern in patterns:
        walker = root.rglob if recursive else root.glob
        for path in walker(pattern):
            if path.is_file():
                files.add(path)
    return sorted(files)


def deduplicate_crashes(triager: CrashTriager, crashes: Iterable[CrashInfo]) -> dict[str, list[CrashInfo]]:
    buckets: dict[str, list[CrashInfo]] = defaultdict(list)
    for crash in crashes:
        key = triager.compute_dedup_key(crash)
        buckets[key].append(crash)
    return buckets


def crash_to_dict(crash: CrashInfo, dedup_key: str, count: int) -> Dict[str, Any]:
    data = asdict(crash)
    data["dedup_key"] = dedup_key
    data["occurrences"] = count
    return data


def write_json(path: Path, buckets: dict[str, list[CrashInfo]]):
    payload = []
    for key, crashes in buckets.items():
        for crash in crashes:
            payload.append(crash_to_dict(crash, key, len(crashes)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(path: Path, buckets: dict[str, list[CrashInfo]]):
    import csv

    rows = []
    for key, crashes in buckets.items():
        for crash in crashes:
            rows.append(
                {
                    "dedup_key": key,
                    "occurrences": len(crashes),
                    "bug_type": crash.bug_type,
                    "trigger_point": crash.trigger_point,
                    "summary": crash.summary,
                    "sanitizer": crash.sanitizer,
                    "harness_name": crash.harness_name,
                    "poc": crash.poc,
                    "target_reached": crash.target_reached,
                }
            )

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)


def render_stdout(buckets: dict[str, list[CrashInfo]]):
    for key, crashes in buckets.items():
        first = crashes[0]
        target_status = "TARGET REACHED" if first.target_reached else "target not reached"
        logger.info(
            "[%s] %s | %s | %s | count=%d | %s",
            key,
            first.bug_type,
            first.trigger_point,
            first.summary.split("\n", 1)[0] if first.summary else "",
            len(crashes),
            target_status,
        )
        for crash in crashes:
            logger.info("    - %s (%s)", crash.poc, crash.harness_name)


def write_crash_report(crash: CrashInfo, output_path: Path, target_function: Optional[str] = None):
    """Write crash report to a text file."""
    lines = []

    # First line: target function status
    if target_function:
        if crash.target_reached:
            lines.append(f"{target_function} function reached")
        else:
            lines.append(f"{target_function} function NOT reached")
    else:
        lines.append("No target function specified")

    lines.append("")
    lines.append(f"Bug Type: {crash.bug_type}")
    lines.append(f"Trigger Point: {crash.trigger_point}")
    lines.append(f"Sanitizer: {crash.sanitizer}")
    lines.append(f"Harness: {crash.harness_name}")
    lines.append(f"PoC: {crash.poc}")
    lines.append(f"Dedup Token: {crash.dup_token}")
    lines.append("")
    lines.append("=== Stack Trace Summary ===")
    lines.append(crash.summary)
    lines.append("")

    if crash.covered_functions:
        # Note: standard library functions are already filtered during extraction
        lines.append("=== Covered Functions ===")
        for func in crash.covered_functions:
            lines.append(f"  {func}")
        lines.append("")

    lines.append("=== Raw Output ===")
    lines.append(crash.raw_output)

    output_path.write_text("\n".join(lines), encoding="utf-8")


def save_unique_crashes(
    buckets: dict[str, list[CrashInfo]],
    output_dir: Path,
    target_function: Optional[str] = None,
):
    """Save unique crash samples and their reports to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for key, crashes in buckets.items():
        # Take the first crash as representative
        crash = crashes[0]
        poc_path = Path(crash.poc)

        if not poc_path.exists():
            logger.warning(f"PoC file not found: {poc_path}")
            continue

        # Copy the crash sample
        sample_name = f"{key}_{poc_path.name}"
        dest_sample = output_dir / sample_name
        shutil.copy2(poc_path, dest_sample)
        logger.info(f"Saved unique sample: {dest_sample}")

        # Write the report
        report_name = f"{sample_name}_report.txt"
        report_path = output_dir / report_name
        write_crash_report(crash, report_path, target_function)
        logger.info(f"Saved report: {report_path}")


def parse_env_vars(env_str: Optional[str]) -> Dict[str, str]:
    """Parse environment variables from string format 'KEY1=VAL1,KEY2=VAL2'."""
    if not env_str:
        return {}
    env_vars = {}
    for pair in env_str.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            env_vars[key.strip()] = value.strip()
    return env_vars


def main():
    parser = argparse.ArgumentParser(
        description="Crash triage and deduplication tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reproduce crashes with binary directly
  %(prog)s --binary ./fuzzer --input ./crashes --output ./unique_crashes

  # Reproduce with target function check
  %(prog)s --binary ./fuzzer --input ./crashes --target-function create_settings --output ./unique

  # Reproduce inside Docker
  %(prog)s --binary ./fuzzer --input ./crashes --docker-image ubuntu:jammy --output ./unique

  # With environment variables
  %(prog)s --binary ./fuzzer --input ./crashes --env "FUZZ_DYN_FUNC=my_func" --output ./unique

  # Parse existing log files (legacy mode)
  %(prog)s --mode log --input ./crash_logs --output ./unique
        """,
    )

    parser.add_argument("--binary", type=Path, help="Path to the fuzzer binary")
    parser.add_argument("--input", required=True, help="Crash file or directory containing crash samples")
    parser.add_argument("--output", type=Path, required=True, help="Output directory for unique samples and reports")
    parser.add_argument("--target-function", help="Target function name to check in coverage output")
    parser.add_argument("--env", help="Environment variables (format: KEY1=VAL1,KEY2=VAL2)")
    parser.add_argument("--docker-image", help="Docker image for reproduction (e.g., ubuntu:jammy)")
    parser.add_argument("--no-coverage", action="store_true", help="Disable -print_coverage=1 flag")

    parser.add_argument(
        "--mode",
        choices=["binary", "log", "reproduce"],
        default="binary",
        help="Mode: 'binary' (reproduce with binary), 'log' (parse logs), 'reproduce' (OSS-Fuzz helper)",
    )

    # Legacy OSS-Fuzz reproduce mode options
    parser.add_argument("--project-name", help="OSS-Fuzz project name (reproduce mode)")
    parser.add_argument("--fuzzer-name", help="Fuzzer name (reproduce mode)")
    parser.add_argument("--oss-fuzz-dir", type=Path, help="Path to OSS-Fuzz checkout (reproduce mode)")

    parser.add_argument("--harness-name", help="Override harness name for all inputs (log mode)")
    parser.add_argument(
        "--pattern",
        action="append",
        default=None,
        help="Glob pattern(s) to search under input directory",
    )
    parser.add_argument("--no-recursive", action="store_true", help="Disable recursive search")
    parser.add_argument("--output-json", type=Path, help="Optional path to write results as JSON")
    parser.add_argument("--output-csv", type=Path, help="Optional path to write results as CSV")
    parser.add_argument("--log-level", default="INFO", help="Logging level")

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )

    # Set default patterns if not specified
    if args.pattern is None:
        args.pattern = ["crash-*", "timeout-*", "oom-*", "*.log", "*.txt", "*"]

    # Validate arguments based on mode
    if args.mode == "binary" and not args.binary:
        parser.error("--binary is required in binary mode")
    if args.mode == "reproduce" and (not args.project_name or not args.fuzzer_name or not args.oss_fuzz_dir):
        parser.error("--project-name, --fuzzer-name, and --oss-fuzz-dir are required in reproduce mode")

    triager = CrashTriager(oss_fuzz_path=args.oss_fuzz_dir)
    input_root = Path(args.input)
    files = iter_input_files(input_root, args.pattern, recursive=not args.no_recursive)

    if not files:
        logger.error("No crash files found under %s", input_root)
        return 1

    env_vars = parse_env_vars(args.env)
    crashes: list[CrashInfo] = []

    for crash_file in files:
        logger.info(f"Processing: {crash_file}")

        if args.mode == "log":
            harness_name = args.harness_name or crash_file.stem
            info = asyncio.run(
                triager.triage_crash_log(crash_file, harness_name, args.target_function)
            )
        elif args.mode == "reproduce":
            info = asyncio.run(
                triager.triage_crash(args.project_name, args.fuzzer_name, crash_file)
            )
        else:  # binary mode
            info = asyncio.run(
                triager.reproduce_with_binary(
                    binary=args.binary,
                    crash_file=crash_file,
                    target_function=args.target_function,
                    env_vars=env_vars,
                    docker_image=args.docker_image,
                    print_coverage=not args.no_coverage,
                )
            )

        if info:
            crashes.append(info)
        else:
            logger.warning("Skipping %s (unparsable or no crash)", crash_file)

    if not crashes:
        logger.error("No crashes could be parsed")
        return 1

    buckets = deduplicate_crashes(triager, crashes)
    render_stdout(buckets)

    # Save unique crashes and reports to output directory
    save_unique_crashes(buckets, args.output, args.target_function)

    if args.output_json:
        write_json(args.output_json, buckets)
        logger.info("Wrote JSON results to %s", args.output_json)

    if args.output_csv:
        write_csv(args.output_csv, buckets)
        logger.info("Wrote CSV results to %s", args.output_csv)

    logger.info(f"Found {len(buckets)} unique crashes from {len(crashes)} total samples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())