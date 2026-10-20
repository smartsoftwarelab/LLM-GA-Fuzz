from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import shutil
import subprocess
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

from langchain_core.language_models import BaseChatModel

from bench_cfg import BenchConfig
from constants import CompileResults, LanguageType, PROJECT_PATH, ValResult
from utils.misc import extract_name
from utils.llm_usage import HTTP_AUDIT_PATH, LoggedChatOpenAI, UsageLog, activate
from utils.run_manifest import RunManifest, config_hash, derive_seed, docker_image_info, git_info

from agent.gen import ISSTAFuzzer
from agent.modules.fuzzenv import FuzzENV
from agent.modules.compilation import CompilerWraper
from agent.modules import fitness as fitness_mod
from agent.modules.fitness import (
    FitnessScores, extract_coverage_from_log, prompt_value,
    configure_fitness, crash_location, fitness_config,
    STATUS_COMPILE_FAILED, STATUS_EVAL_ERROR, STATUS_EVAL_SKIPPED,
)
from agent.modules.population import (
    Archive, HarnessGenome,
    OP_CROSSOVER, OP_INITIAL, OP_CACHED, OP_MUTATION, OP_REPAIR,
)
from agent.modules.variation import (
    CrossoverOperator, MutationOperator, MUTATION_STRATEGIES, STRATEGY_NAMES, choose_strategy,
)
from agent_tools.fuzz_tools.run_fuzzer import FuzzerRunner, LIBFUZZER_SEED
from agent_tools.fuzz_tools.llvm_cov import library_scope_root


# Default evolutionary hyper-parameters (overridden via YAML config)
EVO_DEFAULTS: dict = {
    "evo_population_size":    5,     # harnesses to generate in phase 1
    "evo_generations":        10,    # evolutionary generations
    "evo_offspring_per_gen":  4,     # offspring produced each generation
    "evo_crossover_prob":     0.40,  # P(crossover) vs P(mutation)
    "evo_tournament_k":       3,     # tournament selection size
    "evo_archive_capacity":   20,    # max archive size
    "evo_elite_count":        2,     # elites copied to next generation
    "evo_fuzz_trial_seconds": 60,    # short fuzz trial for fitness (seconds)
    "evo_convergence_window": 3,     # stop if no improvement for N gens
}


# Shared evaluation environment

class _EvalEnv(FuzzENV):
    """
    A lightweight FuzzENV used exclusively for compiling and fuzzing offspring.
    Created ONCE and reused across all evaluations in the evolutionary loop.

    Uses eval_flag=False so harness_pairs and code_retriever are available
    (needed by CompilerWraper even with compile_enhance=False).
    """

    def __init__(
        self,
        benchcfg: BenchConfig,
        function_signature: str,
        project_name: str,
        n_run: int,
    ):
        super().__init__(benchcfg, function_signature, project_name, n_run, force_init=True)

    def make_compiler(self) -> CompilerWraper:
        return CompilerWraper(
            oss_fuzz_dir      = self.benchcfg.oss_fuzz_dir,
            benchmark_dir     = self.benchcfg.benchmark_dir,
            project_name      = self.project_name,
            new_project_name  = self.new_project_name,
            code_retriever    = self.code_retriever,
            project_lang      = self.project_lang,
            harness_dict      = self.harness_pairs,
            compile_enhance   = False,   # keep simple; no LSP-based error expansion
            save_dir          = self.save_dir,
            cache_dir         = self.benchcfg.cache_root,
            logger            = self.logger,
        )

    def make_runner(self, fuzz_seconds: int) -> FuzzerRunner:
        fuzz_minutes = max(1, fuzz_seconds // 60)
        return FuzzerRunner(
            oss_fuzz_dir     = self.benchcfg.oss_fuzz_dir,
            new_project_name = self.new_project_name,
            project_lang     = self.project_lang,
            run_timeout      = fuzz_minutes,
            save_dir         = self.save_dir,
        )


# EvoISSTAFuzzer

class EvoISSTAFuzzer:
    """
    Evolutionary fuzzing harness generator.

    Usage
    -----
    >>> evo = EvoISSTAFuzzer(benchcfg, "int foo(const uint8_t*, size_t)", "mylib")
    >>> best = evo.run()
    """

    def __init__(
        self,
        benchcfg: BenchConfig,
        function_signature: str,
        project_name: str,
    ):
        self.benchcfg           = benchcfg
        self.function_signature = function_signature
        self.project_name       = project_name

        # Merge user config with defaults
        self.ecfg: dict = {
            k: benchcfg.config.get(k, v) for k, v in EVO_DEFAULTS.items()
        }

        # Persistent save directory for evolutionary artefacts
        func_name = extract_name(
            function_signature, keep_namespace=True, language=benchcfg.language
        ).replace("::", "_")
        self.evo_dir: Path = (
            benchcfg.save_root
            / project_name.lower()
            / func_name.lower()
            / "evolution"
        )
        self.evo_dir.mkdir(parents=True, exist_ok=True)
        self.target_dir: Path = self.evo_dir.parent   # run1_*/ initial runs, evolution/, manifest, usage log

        self.logger = self._setup_logger()

        # Run identity, seeding and per-request LLM usage log
        self.target_id = f"{project_name}::{function_signature}"
        self.run_id    = f"{uuid.uuid4().hex[:12]}"
        self.seed      = derive_seed(benchcfg.seed, self.target_id) if benchcfg.seed is not None else None
        if self.seed is not None:
            random.seed(self.seed)
        # fresh fitness-normalisation pool + crash-bonus lambda for this run
        configure_fitness(benchcfg.fitness_normalization, benchcfg.crash_bonus, benchcfg.rrf_k,
                          benchcfg.near_init_execs_per_job)
        self.usage_log = activate(UsageLog(self.target_dir / "usage_log.jsonl", self.run_id, self.target_id))
        self.initial_attempts: list[dict] = []
        self.manifest: Optional[RunManifest] = None
        self.archive = Archive(capacity=self.ecfg["evo_archive_capacity"])
        self.generation_stats: list[dict] = []

        # LLM + variation operators
        self.llm          = self._load_llm()
        self.mutation_op  = MutationOperator(self.llm, self.logger)
        self.crossover_op = CrossoverOperator(self.llm, self.logger)

        # Shared evaluation environment (built once, reused for all offspring)
        self._eval_env: Optional[_EvalEnv] = None

    
    # Logging
    

    def _setup_logger(self) -> logging.Logger:
        name   = f"EvoFuzzer.{self.project_name}"
        logger = logging.getLogger(name)
        if logger.handlers:
            return logger
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        # file handler
        fh = logging.FileHandler(self.evo_dir / "evo.log", encoding="utf-8")
        fh.setFormatter(fmt)
        # console handler
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

    
    # LLM loading  (mirrors ISSTAFuzzer.load_model)
    

    def _load_llm(self) -> BaseChatModel:
        cfg = self.benchcfg
        if cfg.model_name == "CoreStableLLM":
            return LoggedChatOpenAI(usage_max_retries=cfg.llm_max_retries,
                api_key    = cfg.llm_api_key,  # type: ignore
                base_url   = cfg.base_url,
                model      = "CoreStableLLM",
                temperature= cfg.temperature,
            )
        if cfg.model_name.startswith("gpt"):
            if "gpt-5-mini" in cfg.model_name:
                return LoggedChatOpenAI(usage_max_retries=cfg.llm_max_retries,
                    api_key = cfg.llm_api_key,  # type: ignore
                    model   = cfg.model_name,
                )
            return LoggedChatOpenAI(usage_max_retries=cfg.llm_max_retries,
                api_key    = cfg.llm_api_key,  # type: ignore
                model      = cfg.model_name,
                temperature= cfg.temperature,
            )
        return LoggedChatOpenAI(usage_max_retries=cfg.llm_max_retries,
            api_key    = os.getenv("OPENROUTER_API_KEY", ""),
            base_url   = "https://openrouter.ai/api/v1",
            model      = cfg.model_name,
            temperature= cfg.temperature,
        )

    
    # Run manifest (static part, collected at runtime)


    def _manifest_static(self) -> dict:
        cfg = self.benchcfg
        snapshot = cfg.snapshot_dict()
        return {
            "run_id":           self.run_id,
            "target_id":        self.target_id,
            "project":          self.project_name,
            "function":         self.function_signature,
            "repetition_index": cfg.repetition_index,
            "seed": {"base_seed": cfg.seed, "seed_source": cfg.seed_source, "target_seed": self.seed,
                     "derivation": "int(sha256(f'{base_seed}:{target_id}')[:8], 16) -> random.seed",
                     "libfuzzer_seed": LIBFUZZER_SEED},
            "config_hash":      config_hash(snapshot),
            "config":           snapshot,
            "code":             git_info(Path(PROJECT_PATH)),
            "oss_fuzz":         git_info(cfg.oss_fuzz_dir),
            "docker_images_start": docker_image_info(),
            "example_selection_cache_start": self._example_cache_digest(),
            "toolchain": {"oss_fuzz_pull_images": cfg.oss_fuzz_pull_images,
                          "build_timings_log": os.environ.get("LLMGA_BUILD_TIMINGS")},
            "llm": {"model_name": cfg.model_name, "base_url": cfg.base_url or None,
                    "temperature_config": cfg.temperature, "reasoning": cfg.reasoning,
                    "llm_max_retries": cfg.llm_max_retries, "http_audit_log": HTTP_AUDIT_PATH,
                    "note": "per-request model/temperature actually sent: usage_log.jsonl and llm_observed_params"},
            "evolution": {**self.ecfg, "strategy_selection": cfg.strategy_selection,
                          "strategy_priority_weight": cfg.strategy_priority_weight},
            "fitness": {"normalization": cfg.fitness_normalization, "crash_bonus_lambda": cfg.crash_bonus,
                        "rrf_k": cfg.rrf_k, "crash_repro_max": cfg.crash_repro_max,
                        "near_init_execs_per_job": cfg.near_init_execs_per_job,
                        "W_COVERAGE": fitness_mod.W_COVERAGE, "W_FEATURES": fitness_mod.W_FEATURES,
                        "W_EXEC": fitness_mod.W_EXEC, "W_STABILITY": fitness_mod.W_STABILITY,
                        "CRASH_BONUS": fitness_mod.CRASH_BONUS, "NORM_COVERAGE": fitness_mod.NORM_COVERAGE,
                        "NORM_FEATURES": fitness_mod.NORM_FEATURES, "NORM_EXEC": fitness_mod.NORM_EXEC},
            "artifacts": {"target_dir": str(self.target_dir), "evolution_dir": str(self.evo_dir),
                          "usage_log": str(self.usage_log.path),
                          "generation_files": "evolution/gen_XXX/<idx>_<genome_id>.json (code + fitness)"},
        }

    def _example_cache_digest(self) -> dict:
        """sha256 of the shared example-ranking cache files for this project/model. Ranking is a
        shared preprocessing step: present at start = reused, absent at start = created by this run."""
        d = Path(self.benchcfg.cache_root) / self.project_name
        model = self.benchcfg.model_name.replace("/", "_")
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(d.glob(f"*_references_*_{model}.json"))} if d.is_dir() else {}

    # Shared evaluation environment


    def _get_eval_env(self) -> _EvalEnv:
        """Lazily create and cache the shared evaluation environment."""
        if self._eval_env is None:
            # Use a fixed n_run=9000 so it doesn't clash with initial population runs
            self._eval_env = _EvalEnv(
                self.benchcfg,
                self.function_signature,
                self.project_name,
                n_run=9000,
            )
        return self._eval_env

    
    # Phase 0: API knowledge extraction
    

    def _get_api_context(self) -> str:
        """
        Return a short string describing the target function's API:
        definition + declaration retrieved via CodeRetriever.
        Used to ground mutation / crossover prompts.
        """
        try:
            env = self._get_eval_env()
            if env.early_exit_flag:
                return f"Target: {self.function_signature}"
            func_name = extract_name(
                self.function_signature,
                keep_namespace=True,
                language=self.benchcfg.language,
            )
            definition  = env.code_retriever.get_symbol_definition(func_name)
            declaration = env.code_retriever.get_symbol_declaration(func_name)
            return f"Declaration:\n{declaration}\n\nDefinition:\n{definition}"
        except Exception as exc:
            self.logger.warning(f"API context extraction failed: {exc}")
            return f"Target function: {self.function_signature}"

    
    # Phase 1: Initial population via ISSTAFuzzer
    

    def _generate_initial_population(self) -> list[HarnessGenome]:
        """
        Run ISSTAFuzzer ``evo_population_size`` times to produce diverse
        initial harnesses.  Each run uses a different n_run index, causing
        ISSTAFuzzer to pick different usage examples (via select_example).
        """
        pop_size = self.ecfg["evo_population_size"]
        self.logger.info(
            f"=== Phase 1: generating initial population ({pop_size} harnesses) ==="
        )
        population: list[HarnessGenome] = []
        self.usage_log.call_type, self.usage_log.generation = "initial_generation", 0

        for i in range(pop_size):
            self.logger.info(
                f"Initial harness {i + 1}/{pop_size}..."
            )
            # one record per attempt, so lost harnesses are explicit in the manifest
            attempt: dict = {"index": i + 1, "status": None, "genome_id": None, "chars": None,
                             "save_dir": None, "error": None}
            self.initial_attempts.append(attempt)
            n_before = len(population)
            base: Optional[ISSTAFuzzer] = None
            try:
                base = ISSTAFuzzer(
                    self.benchcfg,
                    self.function_signature,
                    self.project_name,
                    n_run=i + 1,
                )
                attempt["save_dir"] = str(base.save_dir)

                if base.early_exit_flag:
                    # NOT a fresh generation: reuses a harness from an earlier run in this save_root
                    attempt["status"] = "CACHED"
                    # Workspace already exists — load cached harness
                    harness_file = base.save_dir / "harness.txt"
                    if harness_file.exists():
                        code = harness_file.read_text(encoding="utf-8")
                        if code.strip():
                            g = HarnessGenome.make(code, 0, [], OP_CACHED)
                            population.append(g)
                            self.logger.info(
                                f"Loaded cached harness {i + 1} ({len(code)} chars)"
                            )
                    continue

                graph = base.build_graph()
                base.run_graph(graph)

                harness_file = base.save_dir / "harness.txt"
                if harness_file.exists():
                    code = harness_file.read_text(encoding="utf-8")
                    if code.strip():
                        g = HarnessGenome.make(code, 0, [], OP_INITIAL)
                        population.append(g)
                        self.logger.info(
                            f"Generated initial harness {i + 1} ({len(code)} chars)"
                        )
                        attempt["status"] = "OK"
                    else:
                        self.logger.warning(
                            f"Harness {i + 1} generated but code is empty."
                        )
                        attempt["status"] = "EMPTY_HARNESS"
                else:
                    self.logger.warning(
                        f"Harness {i + 1}: harness.txt not found."
                    )
                    attempt["status"] = "NO_HARNESS_FILE"

            except Exception as exc:
                self.logger.error(
                    f"Failed to generate initial harness {i + 1}: {exc}"
                )
                traceback.print_exc()
                attempt["status"] = "EXCEPTION"
                attempt["error"] = f"{type(exc).__name__}: {exc}"[:500]
            finally:
                if len(population) > n_before:
                    attempt["genome_id"] = population[-1].genome_id
                    attempt["chars"] = len(population[-1].code)
                elif attempt["status"] == "CACHED":
                    attempt["status"] = "CACHED_EMPTY"
                if base and not base.early_exit_flag:
                    try:
                        base.clean_workspace()
                    except Exception:
                        pass

        self.logger.info(
            f"Initial population: {len(population)}/{pop_size} harnesses generated."
        )
        return population

    
    # Phase 2: Evaluation (compile + short fuzz trial)
    

    def _evaluate(
        self,
        genome: HarnessGenome,
        counter: int,
        eval_save_dir: Path,
    ) -> HarnessGenome:
        """
        Compile and run a short fuzz trial for one genome.
        Populates genome.fitness, genome.compile_ok, genome.compile_error.
        """
        self.logger.info(
            f"Evaluating genome {genome.genome_id}  "
            f"(gen={genome.generation}, op={genome.operation})"
        )

        eval_save_dir.mkdir(parents=True, exist_ok=True)

        try:
            env = self._get_eval_env()
            if env.early_exit_flag:
                self.logger.warning("Eval env early-exit; skipping evaluation.")
                genome.fitness = FitnessScores(status=STATUS_EVAL_SKIPPED,
                                               error_message="evaluation environment early exit")
                return genome

            compiler = env.make_compiler()
            # Override save_dir so logs go to genome-specific folder
            compiler.save_dir = eval_save_dir

            harness_path = list(env.harness_pairs.values())[0]
            fuzzer_name  = list(env.harness_pairs.keys())[0]

            state: dict = {
                "harness_code": genome.code,
                "fix_counter":  counter,
                "fuzzer_name":  fuzzer_name,
                "fuzzer_path":  harness_path,
            }

            # ---- compile ----
            result    = compiler.compile(state)
            compile_msg = result["messages"][1]

            if compile_msg != CompileResults.Success.value:
                genome.compile_ok    = False
                genome.compile_error = result.get("build_msg", compile_msg)
                genome.fitness       = FitnessScores(compile_ok=False, status=STATUS_COMPILE_FAILED)
                self.logger.info(
                    f"  COMPILE FAILED — {compile_msg[:80]}"
                )
                return genome

            genome.compile_ok = True
            used_fuzzer = result.get("fuzzer_name", fuzzer_name)

            # ---- short fuzz trial ----
            runner = env.make_runner(self.ecfg["evo_fuzz_trial_seconds"])
            runner.save_dir = eval_save_dir   # per-genome log dir

            self.logger.info(
                f"  Running {self.ecfg['evo_fuzz_trial_seconds']}s fuzz trial..."
            )
            trial_start = time.time()
            fuzz_result, error_lines, stacks = runner.run_fuzzing(
                counter, used_fuzzer, ignore_crashes=True, no_log=False
            )

            # ---- extract coverage + classify crashes ----
            log_path   = eval_save_dir / f"fuzzing{counter}.log"
            scope_root = library_scope_root(harness_path, self.project_name)
            fitness    = extract_coverage_from_log(log_path, scope_root=scope_root, harness_path=str(harness_path))
            fitness.compile_ok = True

            if fuzz_result == ValResult.Crash:
                fitness.crash_found = True
            if "sanitizer" in fitness.crash_events and fitness.crash_location == "unknown":
                # fork-mode logs have no stack traces: reproduce the saved crash inputs
                self._locate_crashes(fitness, env, used_fuzzer, str(harness_path), scope_root,
                                     trial_start, eval_save_dir)
            fitness_config().observe(fitness)

            genome.fitness       = fitness
            genome.fuzz_log_path = str(log_path)

            exec_s = "None" if fitness.exec_per_sec is None else f"{fitness.exec_per_sec:.0f}"
            self.logger.info(
                f"  {genome.genome_id}: status={fitness.status}, cov={fitness.coverage}, "
                f"ft={fitness.features}, exec/s={exec_s}, "
                f"crash_events={fitness.crash_events}, library_crash={fitness.library_crash}, "
                f"total_fitness={fitness.total():.4f}"
            )

        except Exception as exc:
            self.logger.error(
                f"Evaluation error for {genome.genome_id}: {exc}"
            )
            traceback.print_exc()
            genome.fitness = FitnessScores(status=STATUS_EVAL_ERROR,
                                           error_message=f"{type(exc).__name__}: {exc}")

        return genome

    def _locate_crashes(self, fitness: FitnessScores, env: "_EvalEnv", fuzzer: str, harness_path: str,
                        scope_root: str, trial_start: float, save_dir: Path) -> None:
        """Reproduce up to crash_repro_max crash inputs written during this trial with
        `helper.py reproduce` (ASan build still in build/out) and classify their stacks."""
        out_dir = Path(self.benchcfg.oss_fuzz_dir) / "build" / "out" / env.new_project_name
        artifacts = sorted((p for p in out_dir.glob("crash-*") if p.stat().st_mtime >= trial_start),
                           key=lambda p: p.stat().st_mtime, reverse=True)[: self.benchcfg.crash_repro_max]
        helper = Path(self.benchcfg.oss_fuzz_dir) / "infra" / "helper.py"
        locations: list[str] = []
        for art in artifacts:
            try:
                proc = subprocess.run(["python3", str(helper), "reproduce", env.new_project_name, fuzzer, str(art)],
                                      capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
                report = proc.stdout + proc.stderr
            except Exception as exc:
                report = f"reproduce failed: {type(exc).__name__}: {exc}"
            shutil.copy(art, save_dir / art.name)
            (save_dir / f"repro_{art.name}.log").write_text(report, encoding="utf-8", errors="replace")
            locations.append(crash_location(report, scope_root, harness_path))
        for loc in ("library", "harness", "other"):
            if loc in locations:
                fitness.apply_crash_location(loc)
                break
        else:
            fitness.apply_crash_location("unknown")
        self.logger.info(f"  crash reproduction: {len(artifacts)} input(s) -> {locations or 'none'}")

    def _evaluate_population(
        self, population: list[HarnessGenome], generation: int
    ) -> list[HarnessGenome]:
        """Evaluate every genome in the list sequentially."""
        evaluated = []
        for i, genome in enumerate(population):
            eval_dir = self.evo_dir / f"gen_{generation:03d}" / genome.genome_id
            genome   = self._evaluate(genome, counter=generation * 100 + i, eval_save_dir=eval_dir)
            evaluated.append(genome)
        return evaluated

    
    # Archive & generation bookkeeping
    

    def _save_generation(
        self, generation: int, population: list[HarnessGenome]
    ) -> None:
        gen_dir = self.evo_dir / f"gen_{generation:03d}"
        gen_dir.mkdir(parents=True, exist_ok=True)

        # determine file extension from eval env if available
        _ext = ".c" if (
            self._eval_env and not self._eval_env.early_exit_flag
            and self._eval_env.project_lang.value == "C"
        ) else ".cpp"
        for i, g in enumerate(population):
            g.save(gen_dir / f"{i:02d}_{g.genome_id}.json")
            if g.code:
                (gen_dir / f"{i:02d}_{g.genome_id}{_ext}").write_text(
                    g.code, encoding="utf-8"
                )

        archive_best = self.archive.best(1)
        # statistics over measured trials only; None when no trial produced statistics
        covs = [g.fitness.coverage for g in population if g.fitness.coverage is not None]
        fts  = [g.fitness.features for g in population if g.fitness.features is not None]
        status_counts: dict = {}
        for g in population:
            status_counts[g.fitness.status] = status_counts.get(g.fitness.status, 0) + 1
        stats: dict = {
            "generation":          generation,
            "population_size":     len(population),
            "n_compiled":          sum(1 for g in population if g.compile_ok),
            "n_with_stats":        len(covs),
            "fitness_status_counts": status_counts,
            "max_coverage":        max(covs, default=None),
            "max_features":        max(fts, default=None),
            "avg_fitness":         (
                sum(g.total_fitness() for g in population) / len(population)
                if population else 0.0
            ),
            "crash_found":         any(g.fitness.crash_found for g in population),
            "library_crash_found": any(g.fitness.library_crash for g in population),
            "fitness_normalization": fitness_config().state(),
            "archive_size":        len(self.archive),
            "archive_best_cov":    archive_best[0].fitness.coverage if archive_best else None,
            "archive_max_features": max((g.fitness.features for g in self.archive.all_valid()
                                         if g.fitness.features is not None), default=None),
            "archive_best_fitness": archive_best[0].total_fitness() if archive_best else 0.0,
        }
        self.generation_stats.append(stats)

        stats_path = self.evo_dir / "generation_stats.json"
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(self.generation_stats, f, indent=2)

        self.logger.info(
            f"Gen {generation:3d} | "
            f"compiled {stats['n_compiled']}/{stats['population_size']} | "
            f"max_cov={stats['max_coverage']} | "
            f"archive_best_cov={stats['archive_best_cov']} | "
            f"crash={stats['crash_found']}"
        )

    
    # Convergence check
    

    def _path_plateau(self, window: int = 3) -> bool:
        """Paper rule 1: archive max features (path diversity) unchanged over `window` generations."""
        recent = [s.get("archive_max_features") for s in self.generation_stats[-window:]]
        return len(recent) == window and None not in recent and len(set(recent)) == 1

    def _converged(self) -> bool:
        window = self.ecfg["evo_convergence_window"]
        if len(self.generation_stats) < window:
            return False
        recent_covs = [s["archive_best_cov"] for s in self.generation_stats[-window:]]
        return len(set(recent_covs)) == 1   # no improvement in last N generations

    
    # Next-generation selection
    

    def _next_generation(
        self,
        current: list[HarnessGenome],
        offspring: list[HarnessGenome],
    ) -> list[HarnessGenome]:
        """
        Combine current population + offspring, keep best via elitism + diversity.
        """
        elite_count = self.ecfg["evo_elite_count"]
        pop_size    = self.ecfg["evo_population_size"]

        elites = self.archive.best(elite_count)
        rest   = sorted(
            [g for g in (current + offspring) if g.compile_ok and g not in elites],
            key=lambda g: g.total_fitness(),
            reverse=True,
        )

        next_pop = list(elites)
        for g in rest:
            if len(next_pop) >= pop_size:
                break
            next_pop.append(g)

        return next_pop

    
    # Phase 3: Evolutionary loop
    

    def _evolve(
        self, population: list[HarnessGenome], api_context: str
    ) -> None:
        """Run the evolutionary generations, updating self.archive in place."""
        generations      = self.ecfg["evo_generations"]
        offspring_per_gen = self.ecfg["evo_offspring_per_gen"]
        crossover_prob   = self.ecfg["evo_crossover_prob"]
        tournament_k     = self.ecfg["evo_tournament_k"]

        for gen in range(1, generations + 1):
            self.usage_log.call_type, self.usage_log.generation = None, gen
            self.logger.info(f"\n{'─' * 50}")
            self.logger.info(f"  Generation {gen}/{generations}")
            self.logger.info(f"{'─' * 50}")

            if len(self.archive) == 0:
                self.logger.warning("Archive empty — cannot produce offspring. Stopping.")
                break

            offspring: list[HarnessGenome] = []

            for child_idx in range(offspring_per_gen):
                try:
                    do_crossover = (
                        random.random() < crossover_prob
                        and len(self.archive) >= 2
                    )

                    # Determine project language for variation operators
                    eval_env = self._get_eval_env()
                    proj_lang = eval_env.project_lang if not eval_env.early_exit_flag else self.benchcfg.language

                    if do_crossover:
                        p1, p2    = self.archive.select_pair(tournament_k)
                        code      = self.crossover_op.crossover(
                            p1, p2, self.function_signature, api_context,
                            project_lang=proj_lang,
                        )
                        child = HarnessGenome.make(
                            code, gen, [p1.genome_id, p2.genome_id], OP_CROSSOVER
                        )
                    else:
                        parent   = self.archive.tournament_select(tournament_k)
                        s_idx, s_rule = choose_strategy(
                            self.benchcfg.strategy_selection, parent.fitness,
                            self._path_plateau(), self.benchcfg.strategy_priority_weight,
                        )
                        strategy = MUTATION_STRATEGIES[s_idx]
                        self.logger.info(
                            f"  strategy={STRATEGY_NAMES[s_idx]} rule={s_rule} "
                            f"(mode={self.benchcfg.strategy_selection}, parent={parent.genome_id})"
                        )
                        cov_fb   = (
                            f"Parent {parent.genome_id} achieved "
                            f"{prompt_value(parent.fitness.coverage)} edges and "
                            f"{prompt_value(parent.fitness.features)} features. "
                            "Try to reach code paths it does not."
                        )
                        code   = self.mutation_op.mutate(
                            parent, strategy,
                            self.function_signature, api_context, cov_fb,
                            project_lang=proj_lang,
                        )
                        child = HarnessGenome.make(
                            code, gen, [parent.genome_id], OP_MUTATION
                        )
                        child.meta = {"strategy": STRATEGY_NAMES[s_idx], "strategy_rule": s_rule,
                                      "strategy_mode": self.benchcfg.strategy_selection}

                    # Evaluate offspring
                    eval_dir = (
                        self.evo_dir
                        / f"gen_{gen:03d}"
                        / child.genome_id
                    )
                    child = self._evaluate(
                        child,
                        counter=gen * 1000 + child_idx,
                        eval_save_dir=eval_dir,
                    )
                    offspring.append(child)

                except Exception as exc:
                    self.logger.error(
                        f"Offspring {child_idx + 1} creation failed: {exc}"
                    )
                    traceback.print_exc()

            # Update archive with new offspring
            self.archive.update(offspring)

            # Save generation artefacts and stats
            self._save_generation(gen, population + offspring)

            # Build next population
            population = self._next_generation(population, offspring)

            # Early stopping
            if self._converged():
                self.logger.info(
                    f"Convergence detected at generation {gen}. "
                    "No improvement in last "
                    f"{self.ecfg['evo_convergence_window']} generations."
                )
                break

    
    # Phase 4: Save final results
    

    def _save_final(self, best: list[HarnessGenome]) -> None:
        final_dir = self.evo_dir / "final"
        final_dir.mkdir(parents=True, exist_ok=True)

        _ext = ".c" if (
            self._eval_env and not self._eval_env.early_exit_flag
            and self._eval_env.project_lang.value == "C"
        ) else ".cpp"
        for i, g in enumerate(best):
            g.save(final_dir / f"best_{i + 1:02d}_{g.genome_id}.json")
            (final_dir / f"best_{i + 1:02d}_{g.genome_id}{_ext}").write_text(
                g.code, encoding="utf-8"
            )

        summary = {
            "function":            self.function_signature,
            "project":             self.project_name,
            "total_generations":   len(self.generation_stats),
            "archive_size":        len(self.archive),
            "best_coverage":       best[0].fitness.coverage  if best else None,
            "best_features":       best[0].fitness.features  if best else None,
            "best_fitness":        best[0].total_fitness()   if best else 0.0,
            "crash_found":         any(
                g.fitness.crash_found for g in self.archive.all_valid()
            ),
            "generation_stats":    self.generation_stats,
        }
        with open(final_dir / "summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        self.logger.info("\n" + "=" * 60)
        self.logger.info("EVOLUTION COMPLETE")
        self.logger.info(f"  Best coverage : {summary['best_coverage']} edges")
        self.logger.info(f"  Best features : {summary['best_features']}")
        self.logger.info(f"  Crash found   : {summary['crash_found']}")
        self.logger.info(f"  Results saved : {final_dir}")
        self.logger.info("=" * 60)

    
    # Public entry point
    

    def run(self) -> list[HarnessGenome]:
        """
        Execute the full evolutionary pipeline.

        Returns the top-5 harnesses from the final archive sorted by fitness.
        """
        self.logger.info("=" * 60)
        self.logger.info(f"EvoISSTAFuzzer  →  {self.project_name}::{self.function_signature}")
        self.logger.info(f"Config: {self.ecfg}")
        self.logger.info("=" * 60)

        self.manifest = RunManifest(self.target_dir / "run_manifest.json", **self._manifest_static())
        status = "failed"
        best: list[HarnessGenome] = []
        try:
            # Phase 0: API context (used in variation prompts)
            with self.manifest.phase("api_context"):
                api_context = self._get_api_context()

            # Phase 1: Initial population
            with self.manifest.phase("initial_generation"):
                population = self._generate_initial_population()
            self.manifest.update(initial_attempts=self.initial_attempts)
            if not population:
                self.logger.error("No harnesses generated in phase 1. Aborting.")
                status = "aborted_no_initial_population"
                return []

            # Phase 2: Evaluate initial population
            self.logger.info("=== Phase 2: Evaluating initial population ===")
            with self.manifest.phase("initial_evaluation"):
                population = self._evaluate_population(population, generation=0)

                # Seed the archive with the evaluated initial population
                self.archive.update(population)
                self._save_generation(0, population)

            # Phase 3: Evolution
            self.logger.info("=== Phase 3: Evolutionary loop ===")
            with self.manifest.phase("evolution"):
                self._evolve(population, api_context)

            # Phase 4: Final results
            with self.manifest.phase("finalize"):
                best = self.archive.best(5)
                self._save_final(best)
            status = "completed"
            return best

        finally:
            self.manifest.finish(
                status,
                initial_attempts=self.initial_attempts,
                generations_run=len(self.generation_stats),
                best_genome_ids=[g.genome_id for g in best],
                llm_requests_logged=self.usage_log.n_records,
                llm_observed_params=[{"model": m, "temperature_sent": t, "response_model": r}
                                     for m, t, r in sorted(self.usage_log.observed_params, key=str)],
                docker_images_end=docker_image_info(),
                example_selection_cache_end=self._example_cache_digest(),
            )
            # Clean up the shared evaluation environment
            if self._eval_env and not self._eval_env.early_exit_flag:
                try:
                    self._eval_env.clean_workspace()
                    self.logger.info("Shared eval environment cleaned up.")
                except Exception as exc:
                    self.logger.warning(f"Cleanup error: {exc}")
                finally:
                    self._eval_env = None  # always reset so next call creates fresh env