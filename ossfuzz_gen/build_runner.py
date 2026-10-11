# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Project local/cloud builder and runner.
"""
import dataclasses
import logging
import re
from collections import defaultdict, namedtuple
from typing import Any, Optional
from pathlib import Path

from ossfuzz_gen.fuzz_target_error import SemanticCheckResult

logger = logging.getLogger(__name__)

# The directory in the oss-fuzz image
JCC_DIR = '/usr/local/bin'
RUN_TIMEOUT: int = 30
CLOUD_EXP_MAX_ATTEMPT = 5

LIBFUZZER_MODULES_LOADED_REGEX = re.compile(
    r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')
LIBFUZZER_COV_REGEX = re.compile(r'.*cov: (\d+) ft:')
LIBFUZZER_CRASH_TYPE_REGEX = re.compile(r'.*Test unit written to.*')
LIBFUZZER_COV_LINE_PREFIX = re.compile(r'^#(\d+)')
LIBFUZZER_STACK_FRAME_LINE_PREFIX = re.compile(r'^\s+#\d+')
CRASH_EXCLUSIONS = re.compile(r'.*(slow-unit-|timeout-|leak-|oom-).*')
CRASH_STACK_WITH_SOURCE_INFO = re.compile(r'in.*:\d+:\d+$')

LIBFUZZER_LOG_STACK_FRAME_LLVM = '/src/llvm-project/compiler-rt'
LIBFUZZER_LOG_STACK_FRAME_LLVM2 = '/work/llvm-stage2/projects/compiler-rt'
LIBFUZZER_LOG_STACK_FRAME_CPP = '/usr/local/bin/../include/c++'

EARLY_FUZZING_ROUND_THRESHOLD = 3

ParseResult = namedtuple(
    'ParseResult',
    ['cov_pcs', 'total_pcs', 'crashes', 'crash_info', 'semantic_check_result'])



class FuzzingLogParser:
    # Regex for extract function name.
  FUNC_NAME = re.compile(r'(?:^|\s|\b)([\w:]+::)*(\w+)(?:<[^>]*>)?(?=\(|$)')
  # Regex for extract line number,
  LINE_NUMBER = re.compile(r':(\d+):')

  def __init__(self, ossfuzz_dir: str, project_name: str):
    self.ossfuzz_dir = ossfuzz_dir
    self.project_name = project_name

  def _parse_stacks_from_libfuzzer_logs(self,
                                        lines: list[str]) -> list[list[str]]:
    """Parses stack traces from libFuzzer logs."""
    # TODO (dongge): Use stack parsing from ClusterFuzz.
    # There can have over one thread stack in a log.
    stacks = []

    # A stack -> a sequence of stack frame lines.
    stack, stack_parsing = [], False
    for line in lines:
      is_stack_frame_line = LIBFUZZER_STACK_FRAME_LINE_PREFIX.match(
          line) is not None
      if (not stack_parsing) and is_stack_frame_line:
        # First line.
        stack_parsing = True
        stack = [line.strip()]
      elif stack_parsing and is_stack_frame_line:
        # Middle line(s).
        stack.append(line.strip())
      elif stack_parsing and (not is_stack_frame_line):
        # Last line.
        stack_parsing = False
        stacks.append(stack)

    # Last stack.
    if stack_parsing:
      stacks.append(stack)

    return stacks

  def _parse_func_from_stacks(self, project_name: str,
                              stacks: list[list[str]]) -> dict[str, set[int]]:
    """Parses project functions from stack traces."""
    func_info = defaultdict(set)

    for stack in stacks:
      for line in stack:
        # Use 3 spaces to divide each line of crash info into four parts.
        # Only parse the fourth part, which includes the function name,
        # file path, and line number.
        parts = line.split(' ', 3)
        if len(parts) < 4:
          continue
        func_and_file_path = parts[3]
        if project_name not in func_and_file_path:
          continue
        func_name, _, file_path = func_and_file_path.partition(' /')
        if func_name == 'LLVMFuzzerTestOneInput':
          line_match = self.LINE_NUMBER.search(file_path)
          if line_match:
            line_number = int(line_match.group(1))
            func_info[func_name].add(line_number)
          else:
            logger.warning('Failed to parse line number from %s in project %s',
                           func_name, project_name)
          break
        if project_name in file_path:
          func_match = self.FUNC_NAME.search(func_name)
          line_match = self.LINE_NUMBER.search(file_path)
          if func_match and line_match:
            func_name = func_match.group(2)
            line_number = int(line_match.group(1))
            func_info[func_name].add(line_number)
          else:
            logger.warning(
                'Failed to parse function name from %s in project %s',
                func_name, project_name)

    return func_info

  def _parse_fuzz_cov_info_from_libfuzzer_logs(
      self,
      lines: list[str]) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Parses cov of INITED & DONE, and round number from libFuzzer logs."""
    initcov, donecov, lastround = None, None, None

    for line in lines:
      if line.startswith('#'):
        # Parses cov line to get the round number.
        match = LIBFUZZER_COV_LINE_PREFIX.match(line)
        roundno = int(match.group(1)) if match else None

        if roundno is not None:
          lastround = roundno
          if 'INITED' in line and 'cov: ' in line:
            initcov = int(line.split('cov: ')[1].split(' ft:')[0])
          elif 'DONE' in line and 'cov: ' in line:
            donecov = int(line.split('cov: ')[1].split(' ft:')[0])

    return initcov, donecov, lastround

  def _stack_func_is_of_testing_project(self, stack_frame: str) -> bool:
    return (bool(CRASH_STACK_WITH_SOURCE_INFO.match(stack_frame)) and
            LIBFUZZER_LOG_STACK_FRAME_LLVM not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_LLVM2 not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_CPP not in stack_frame)

  def parse_libfuzzer_logs(self,
                            lines: list[str],
                            project_name: str,
                            check_cov_increase: bool = True) -> ParseResult:
    """Parses libFuzzer logs."""

    cov_pcs, total_pcs, crashes = 0, 0, False

    for line in lines:
      m = LIBFUZZER_MODULES_LOADED_REGEX.match(line)
      if m:
        total_pcs = int(m.group(2))
        continue

      m = LIBFUZZER_COV_REGEX.match(line)
      if m:
        cov_pcs = int(m.group(1))
        continue

      m = LIBFUZZER_CRASH_TYPE_REGEX.match(line)
      if m and not CRASH_EXCLUSIONS.match(line):
        # TODO(@happy-qop): Handling oom, slow cases in semantic checks & fix.
        crashes = True
        continue

    initcov, donecov, lastround = self._parse_fuzz_cov_info_from_libfuzzer_logs(
        lines)

    # NOTE: Crashes from incorrect fuzz targets will not be counted finally.

    if crashes:
      symptom = SemanticCheckResult.extract_symptom(fuzzlog)
      crash_stacks = self._parse_stacks_from_libfuzzer_logs(lines)
      crash_func = self._parse_func_from_stacks(project_name, crash_stacks)
      crash_info = SemanticCheckResult.extract_crash_info(fuzzlog)

      # FP case 1: Common fuzz target errors.
      # Null-deref, normally indicating inadequate parameter initialization or
      # wrong function usage.
      if symptom == 'null-deref':
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.NULL_DEREF, symptom,
                                crash_stacks, crash_func))

      # Signal, normally indicating assertion failure due to inadequate
      # parameter initialization or wrong function usage.
      if symptom == 'signal':
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.SIGNAL, symptom,
                                crash_stacks, crash_func))

      # Exit, normally indicating the fuzz target exited in a controlled manner,
      # blocking its bug discovery.
      if symptom.endswith('fuzz target exited'):
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.EXIT, symptom, crash_stacks,
                                crash_func))

      # Fuzz target modified constants.
      if symptom.endswith('fuzz target overwrites its const input'):
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.OVERWRITE_CONST, symptom,
                                crash_stacks, crash_func))

      # OOM, normally indicating malloc's parameter is too large, e.g., because
      # of using parameter `size`.
      # TODO(dongge): Refine this, 1) Merge this with the other oom case found
      # from reproducer name; 2) Capture the actual number in (malloc(\d+)).
      if 'out-of-memory' in symptom or 'out of memory' in symptom:
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.FP_OOM, symptom,
                                crash_stacks, crash_func))

      # FP case 2: fuzz target crashes at init or first few rounds.
      if lastround is None or lastround <= EARLY_FUZZING_ROUND_THRESHOLD:
        # No cov line has been identified or only INITED round has been passed.
        # This is very likely the false positive cases.
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.FP_NEAR_INIT_CRASH, symptom,
                                crash_stacks, crash_func))

      # FP case 3: no func in 1st thread stack belongs to testing proj.
      if len(crash_stacks) > 0:
        first_stack = crash_stacks[0]
        for stack_frame in first_stack:
          if self._stack_func_is_of_testing_project(stack_frame):
            if 'LLVMFuzzerTestOneInput' in stack_frame:
              return ParseResult(
                  cov_pcs, total_pcs, True, crash_info,
                  SemanticCheckResult(SemanticCheckResult.FP_TARGET_CRASH,
                                      symptom, crash_stacks, crash_func))
            break

      return ParseResult(
          cov_pcs, total_pcs, True, crash_info,
          SemanticCheckResult(SemanticCheckResult.NO_SEMANTIC_ERR, symptom,
                              crash_stacks, crash_func))

    if check_cov_increase and initcov == donecov and lastround is not None:
      # Another error fuzz target case: no cov increase.
      # A special case is initcov == donecov == None, which indicates no
      # interesting inputs were found. This may happen if the target rejected
      # all inputs we tried.
      return ParseResult(
          cov_pcs, total_pcs, False, '',
          SemanticCheckResult(SemanticCheckResult.NO_COV_INCREASE))

    return ParseResult(cov_pcs, total_pcs, crashes, '',
                       SemanticCheckResult(SemanticCheckResult.NO_SEMANTIC_ERR))



if __name__ == "__main__":
    # Example usage
    ossfuzz_dir = "/home/ubuntu/fuzzing_workspace/oss-fuzz"
    project_name = "bind9"
    parser = FuzzingLogParser(ossfuzz_dir, project_name)
    
    # Assuming you have a log file to parse
    log_file_path = Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs_ablation/gpt41/header/agent/bind9/dns_name_fromwire/run2_jbipqscilmwukzbu/fuzzing3.log")
    parse_result = parser._parse_libfuzzer_logs(log_file_path, project_name)

    print(parse_result[-1].type)  # Output the parsing result
    print(parse_result[-1].crash_stacks)  # Output the parsing result