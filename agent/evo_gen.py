from __future__ import annotations

import json
import logging
import os
import random
import shutil
import traceback
from pathlib import Path
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.language_models import BaseChatModel

from bench_cfg import BenchConfig
from constants import CompileResults, LanguageType, PROJECT_PATH, ValResult
from utils.misc import extract_name

from agent.gen import ISSTAFuzzer
from agent.modules.fuzzenv import FuzzENV
from agent.modules.compilation import CompilerWraper
from agent.modules.fitness import FitnessScores, extract_coverage_from_log
from agent.modules.population import (
    Archive, HarnessGenome,
    OP_CROSSOVER, OP_INITIAL, OP_CACHED, OP_MUTATION, OP_REPAIR,
)
from agent.modules.variation import (
    CrossoverOperator, MutationOperator, MUTATION_STRATEGIES,
)
from agent_tools.fuzz_tools.run_fuzzer import FuzzerRunner


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

        self.logger = self._setup_logger()
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
            return ChatOpenAI(
                api_key    = cfg.llm_api_key,  # type: ignore
                base_url   = cfg.base_url,
                model      = "CoreStableLLM",
                temperature= cfg.temperature,
            )
        if cfg.model_name.startswith("gpt"):
            if "gpt-5-mini" in cfg.model_name:
                return ChatOpenAI(
                    api_key = cfg.llm_api_key,  # type: ignore
                    model   = cfg.model_name,
                )
            return ChatOpenAI(
                api_key    = cfg.llm_api_key,  # type: ignore
                model      = cfg.model_name,
                temperature= cfg.temperature,
            )
        return ChatOpenAI(
            api_key    = os.getenv("OPENROUTER_API_KEY", ""),
            base_url   = "https://openrouter.ai/api/v1",
            model      = cfg.model_name,
            temperature= cfg.temperature,
        )

    
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

        for i in range(pop_size):
            self.logger.info(
                f"Initial harness {i + 1}/{pop_size}..."
            )
            base: Optional[ISSTAFuzzer] = None
            try:
                base = ISSTAFuzzer(
                    self.benchcfg,
                    self.function_signature,
                    self.project_name,
                    n_run=i + 1,
                )

                if base.early_exit_flag:
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
                    else:
                        self.logger.warning(
                            f"Harness {i + 1} generated but code is empty."
                        )
                else:
                    self.logger.warning(
                        f"Harness {i + 1}: harness.txt not found."
                    )

            except Exception as exc:
                self.logger.error(
                    f"Failed to generate initial harness {i + 1}: {exc}"
                )
                traceback.print_exc()
            finally:
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
                genome.fitness       = FitnessScores(compile_ok=False)
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
            fuzz_result, error_lines, stacks = runner.run_fuzzing(
                counter, used_fuzzer, ignore_crashes=True, no_log=False
            )

            # ---- extract coverage ----
            log_path = eval_save_dir / f"fuzzing{counter}.log"
            fitness  = extract_coverage_from_log(log_path)
            fitness.compile_ok = True

            if fuzz_result == ValResult.Crash:
                fitness.crash_found = True

            genome.fitness       = fitness
            genome.fuzz_log_path = str(log_path)

            self.logger.info(
                f"  {genome.genome_id}: cov={fitness.coverage}, "
                f"ft={fitness.features}, exec/s={fitness.exec_per_sec:.0f}, "
                f"crash={fitness.crash_found}, "
                f"total_fitness={fitness.total():.4f}"
            )

        except Exception as exc:
            self.logger.error(
                f"Evaluation error for {genome.genome_id}: {exc}"
            )
            traceback.print_exc()

        return genome

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
        stats: dict = {
            "generation":          generation,
            "population_size":     len(population),
            "n_compiled":          sum(1 for g in population if g.compile_ok),
            "max_coverage":        max((g.fitness.coverage for g in population), default=0),
            "max_features":        max((g.fitness.features for g in population), default=0),
            "avg_fitness":         (
                sum(g.total_fitness() for g in population) / len(population)
                if population else 0.0
            ),
            "crash_found":         any(g.fitness.crash_found for g in population),
            "archive_size":        len(self.archive),
            "archive_best_cov":    archive_best[0].fitness.coverage if archive_best else 0,
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
                        strategy = random.choice(MUTATION_STRATEGIES)
                        cov_fb   = (
                            f"Parent {parent.genome_id} achieved "
                            f"{parent.fitness.coverage} edges and "
                            f"{parent.fitness.features} features. "
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
            "best_coverage":       best[0].fitness.coverage  if best else 0,
            "best_features":       best[0].fitness.features  if best else 0,
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

        try:
            # Phase 0: API context (used in variation prompts)
            api_context = self._get_api_context()

            # Phase 1: Initial population
            population = self._generate_initial_population()
            if not population:
                self.logger.error("No harnesses generated in phase 1. Aborting.")
                return []

            # Phase 2: Evaluate initial population
            self.logger.info("=== Phase 2: Evaluating initial population ===")
            population = self._evaluate_population(population, generation=0)

            # Seed the archive with the evaluated initial population
            self.archive.update(population)
            self._save_generation(0, population)

            # Phase 3: Evolution
            self.logger.info("=== Phase 3: Evolutionary loop ===")
            self._evolve(population, api_context)

            # Phase 4: Final results
            best = self.archive.best(5)
            self._save_final(best)
            return best

        finally:
            # Clean up the shared evaluation environment
            if self._eval_env and not self._eval_env.early_exit_flag:
                try:
                    self._eval_env.clean_workspace()
                    self.logger.info("Shared eval environment cleaned up.")
                except Exception as exc:
                    self.logger.warning(f"Cleanup error: {exc}")
                finally:
                    self._eval_env = None  # always reset so next call creates fresh env