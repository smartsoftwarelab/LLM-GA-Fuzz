from constants import PROJECT_PATH, LanguageType
from enum import Enum
from pathlib import Path
from typing import Any
import os
import re
import sys
import yaml


REDACTED = "<REDACTED>"
# Secret field names (case-insensitive). "token" matches only as the trailing word
# (github_token, access_token) so model_token_limit / usage_token_limit stay visible.
_SECRET_KEY_RE = re.compile(r"api[_-]?key|secret|(?:^|_)token$", re.IGNORECASE)
# Backstop for secrets stored under an unexpected field name.
_SECRET_VALUE_RE = re.compile(r"sk-[A-Za-z0-9_-]{16,}")


def redact_secrets(obj: Any) -> Any:
    """Return a copy of obj with secret fields replaced by REDACTED, recursing into dicts and lists."""
    if isinstance(obj, dict):
        return {k: REDACTED if isinstance(k, str) and _SECRET_KEY_RE.search(k) else redact_secrets(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_secrets(v) for v in obj]
    if isinstance(obj, str):
        return _SECRET_VALUE_RE.sub(REDACTED, obj)
    return obj


def _to_plain(obj: Any) -> Any:
    """Convert Path/Enum members to YAML-safe builtins."""
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    return obj


class BenchConfig:
    def __init__(self, config_path: str):
        """Initialize the BenchConfig with configuration from a YAML file.
        Args:
            config_path (str): Path to the YAML configuration file
        """
        self.config = self._load_config(config_path)
        
        # Initialize all parameters as class members with defaults from config
        self.oss_fuzz_dir = Path(self.config.get('oss_fuzz_dir', f'/home/ubuntu/fuzzing_workspace/oss-fuzz/'))
        self.cache_root = Path(self.config.get('cache_root', os.path.join(PROJECT_PATH, "cache")))
        self.benchmark_dir = Path( self.config.get('bench_dir', os.path.join(PROJECT_PATH, "benchmark-sets", "ntu")))
        self.save_root = Path(self.config.get('save_root', ""))

        # absolute path
        if not self.save_root.is_absolute():
            self.save_root = PROJECT_PATH /  self.save_root

        self.model_name = self.config.get('model_name', "gpt-5-mini")
        self.base_url = self.config.get('base_url', "")
        # The API key is read only from the environment, never from config files or source.
        if 'llm_api_key' in self.config:
            sys.exit(f"ERROR: {config_path} contains 'llm_api_key'. API keys must not be stored in "
                     "config files: delete that line and export OPENAI_API_KEY instead.")
        self.llm_api_key = os.environ.get("OPENAI_API_KEY")
        if not self.llm_api_key:
            sys.exit("ERROR: environment variable OPENAI_API_KEY is not set (it is also the key used "
                     "for base_url endpoints such as CoreStableLLM). Set it with: export OPENAI_API_KEY=<key>")
        self.llm_max_retries = self.config.get('llm_max_retries', 2)  # retries per request after the first attempt
        self.reasoning = self.config.get('reasoning', False)
        self.temperature = self.config.get('temperature', 0.7)
        self.run_time = self.config.get('run_time', 1)
        self.max_fix = self.config.get('max_fix', 5)
        self.max_tool_call = self.config.get('max_tool_call', 15)
        self.usage_token_limit = self.config.get('usage_token_limit', 1000)
        self.model_token_limit = self.config.get('model_token_limit', 8096)
        self.n_examples = self.config.get('n_examples', 1)
        self.funcs_per_project = self.config.get('funcs_per_project', 1)
        self.example_mode = self.config.get('example_mode', "rank")
        self.example_source = self.config.get('example_source', "project")
        self.iterations = self.config.get('iterations', 3)
        self.num_processes = self.config.get('num_processes', (os.cpu_count() or 4) // 3)
        self.project_name = self.config.get('project_name', [])
        self.function_signatures = self.config.get('function_signatures', [])
        self.language = LanguageType(self.config.get('language', "CPP"))
        self.fixing_mode = self.config.get('fixing_mode', "issta")

        self.clear_msg_flag = self.config.get('clear_msg_flag', True)
        self.header_mode = self.config.get('header_mode', "agent")
        self.memory_flag = self.config.get('memory_flag', False)
        self.definition_flag = self.config.get('definition_flag', False)
        self.driver_flag = self.config.get('driver_flag', False)
        self.compile_enhance = self.config.get('compile_enhance', False)
        # if True, only use semantic check for evaluation
        self.semantic_mode = self.config.get('semantic_mode', "both")
        self.use_cache_harness_pairs = self.config.get('use_cache_harness_pairs', True)

        # for fuzzing
        self.no_log = self.config.get('no_log', False)
        self.ignore_crashes = self.config.get('ignore_crashes', False)

        # fitness (agent/modules/fitness.py): normalisation, crash bonus lambda, crash reproduction
        self.fitness_normalization = self.config.get('fitness_normalization', "pool_max")
        if self.fitness_normalization not in ("pool_max", "fixed", "rrf"):
            sys.exit(f"ERROR: fitness_normalization must be pool_max|fixed|rrf, got {self.fitness_normalization!r}")
        self.crash_bonus = float(self.config.get('crash_bonus', 0.60))   # lambda; 0 for the ablation
        self.rrf_k = int(self.config.get('rrf_k', 60))
        self.crash_repro_max = int(self.config.get('crash_repro_max', 3))  # crash inputs reproduced per trial

        # mutation strategy selection (agent/modules/variation.py: choose_strategy)
        self.strategy_selection = self.config.get('strategy_selection', "profile")   # profile | random (ablation)
        if self.strategy_selection not in ("profile", "random"):
            sys.exit(f"ERROR: strategy_selection must be profile|random, got {self.strategy_selection!r}")
        self.strategy_priority_weight = float(self.config.get('strategy_priority_weight', 3.0))

        # pinned toolchain: do not pull newer OSS-Fuzz base images during a run (utils/oss_fuzz_utils.py)
        self.oss_fuzz_pull_images = bool(self.config.get('oss_fuzz_pull_images', False))
        os.environ["LLMGA_OSSFUZZ_PULL"] = "1" if self.oss_fuzz_pull_images else "0"

        # for reported coverage (llvm-cov on the final corpus, agent/eval.py)
        self.coverage_metric = self.config.get('coverage_metric', "branches")
        if self.coverage_metric not in ("branches", "regions", "lines", "functions"):
            sys.exit(f"ERROR: coverage_metric must be branches|regions|lines|functions, got {self.coverage_metric!r}")
        self.coverage_input_timeout = self.config.get('coverage_input_timeout', 25)    # seconds per replayed input
        self.coverage_total_timeout = self.config.get('coverage_total_timeout', 3600)  # seconds for the whole replay

        # provenance of one run (recorded in run_manifest.json); CLI flags may override
        self.seed = self.config.get('seed', None)                 # base seed; None -> generated at start
        self.seed_source = "config" if self.seed is not None else None
        self.repetition_index = self.config.get('repetition_index', 0)

        # for extracting all functions from project (skip generation)
        self.extract_all_functions = self.config.get('extract_all_functions', False)

    def _load_config(self, config_path: str) -> dict[str, Any]:
        """Load configuration from a YAML file."""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def snapshot_dict(self) -> dict[str, Any]:
        """Plain, secret-redacted view of the configuration, safe to write to disk."""
        return redact_secrets(_to_plain(vars(self)))

    def write_snapshot(self, path: str | os.PathLike) -> None:
        """Write the redacted configuration snapshot as plain YAML."""
        with open(path, 'w') as f:
            yaml.safe_dump(self.snapshot_dict(), f, sort_keys=True)
    
