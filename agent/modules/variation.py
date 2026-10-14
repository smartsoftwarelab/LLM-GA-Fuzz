from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage

from agent.modules.fitness import prompt_value
from agent.modules.population import HarnessGenome
from constants import PROJECT_PATH, LanguageType


# Mutation strategy catalogue
# Each strategy is a natural-language instruction sent to the LLM.
# They cover the main axes of harness diversity identified in the paper.

MUTATION_STRATEGIES: list[str] = [
    # -- Input consumption --
    "Restructure input consumption: change the order in which fuzz data "
    "is extracted from the input buffer (e.g., consume sizes before content, or vice versa).",

    "Change buffer-size boundaries: exercise edge cases by testing with "
    "0-byte, 1-byte, 255-byte, 256-byte, and 65535-byte buffers "
    "(use ConsumeIntegralInRange for C++, or size comparisons for C).",

    "Switch between different string/bytes extraction strategies: vary how "
    "null-terminated strings vs raw byte buffers are derived from the fuzz input, "
    "to exercise different null-termination and encoding paths.",

    # -- API call patterns --
    "Add a loop: call the target function multiple times within a single "
    "LLVMFuzzerTestOneInput invocation, using different slices of the fuzz data "
    "each iteration.",

    "Add NULL-pointer guard checks before every pointer dereference and before "
    "every API call that may not accept NULL arguments.",

    "Add error-path handling: check return values after every API call and follow "
    "the failure branch (e.g., call a cleanup function, return early, or log an "
    "error without aborting).",

    # -- State management --
    "Add cleanup-and-reinitialise: free the current object, reallocate it, and "
    "call the target function again — exercising reuse and double-initialisation paths.",

    "Introduce pre-call state manipulation: set object fields or call a setter "
    "function before invoking the target, to reach deeper internal states.",

    # -- Initialisation / teardown --
    "Wrap global initialisation in a static variable so it runs only once; move "
    "all per-call resources (contexts, buffers) inside the fuzzer loop to prevent OOM.",

    # -- Structural variation --
    "Split the fuzz input into multiple independent segments and use each segment "
    "for a different parameter of the target function, maximising parameter-space "
    "coverage.",
]


# Helpers

def _load_template(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _fill(template: str, **kwargs: str) -> str:
    """
    Simple placeholder substitution using <KEY> syntax.
    Safe for C/C++ source code (which contains { and }).
    """
    for key, value in kwargs.items():
        template = template.replace(f"<{key}>", value)
    return template


def _build_language_note(project_lang: LanguageType) -> str:
    """Build a language-specific note for mutation/crossover prompts."""
    if project_lang == LanguageType.C:
        return (
            "This is a C project. The harness file has a .c extension and may be compiled by "
            "clang++ (C++ compiler). You MUST use the following entry point pattern EXACTLY:\n\n"
            "    #ifdef __cplusplus\n"
            "    extern \"C\" {\n"
            "    #endif\n\n"
            "    int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
            "        /* your implementation */\n"
            "    }\n\n"
            "    #ifdef __cplusplus\n"
            "    }\n"
            "    #endif\n\n"
            "Do NOT use FuzzedDataProvider — use the raw Data pointer and Size directly.\n"
            "Do NOT write 'extern \"C\"' without the '#ifdef __cplusplus' guard."
        )
    else:  # CPP
        return (
            "This is a C++ project. The harness must be valid C++ and use:\n\n"
            "    extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)\n\n"
            "You may use FuzzedDataProvider from <fuzzer/FuzzedDataProvider.h> to extract typed values."
        )


def _extract_cpp_code(response_text: str) -> str:
    """
    Extract the first C/C++ code block from an LLM response.
    Falls back to returning the raw response if no code fence is found.
    """
    patterns = [
        r"```(?:cpp|c\+\+|c)\n(.*?)```",
        r"```\n(.*?)```",
    ]
    for pattern in patterns:
        m = re.search(pattern, response_text, re.DOTALL)
        if m:
            return m.group(1).strip()

    # Heuristic fallback: everything from the first #include onward
    m = re.search(r"(#include\b.*)", response_text, re.DOTALL)
    if m:
        return m.group(1).strip()

    return response_text.strip()


# MutationOperator
class MutationOperator:
    """
    LLM-based harness mutation.

    Reads ``mutation_prompt.txt``, fills in the parent harness and a randomly
    chosen mutation strategy, and returns the LLM-generated mutated code.
    """

    PROMPT_PATH = Path(PROJECT_PATH) / "agent" / "prompts" / "mutation_prompt.txt"

    def __init__(self, llm: BaseChatModel, logger: logging.Logger):
        self.llm    = llm
        self.logger = logger
        self._template = _load_template(self.PROMPT_PATH)

    def mutate(
        self,
        parent: HarnessGenome,
        strategy: str,
        function_signature: str,
        api_context: str   = "",
        coverage_feedback: str = "",
        project_lang: LanguageType = LanguageType.CPP,
    ) -> str:
        """
        Apply ``strategy`` to ``parent`` via the LLM.

        Returns the mutated C++ source code, or the parent's code unchanged
        if the LLM call fails.
        """
        prompt = _fill(
            self._template,
            FUNCTION_SIGNATURE  = function_signature,
            PARENT_CODE         = parent.code,
            MUTATION_STRATEGY   = strategy,
            API_CONTEXT         = api_context or "(none)",
            COVERAGE_FEEDBACK   = coverage_feedback or "(none)",
            PARENT_COVERAGE     = prompt_value(parent.fitness.coverage),
            PARENT_FEATURES     = prompt_value(parent.fitness.features),
            LANGUAGE_NOTE       = _build_language_note(project_lang),
        )

        self.logger.info(
            f"[Mutation] genome={parent.genome_id}  "
            f"strategy='{strategy[:55]}...'"
        )

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            mutated  = _extract_cpp_code(response.content)
            self.logger.info(
                f"[Mutation] success — output length: {len(mutated)} chars"
            )
            return mutated
        except Exception as exc:
            self.logger.error(f"[Mutation] LLM call failed: {exc}")
            return parent.code   # safe fallback: unchanged parent


# CrossoverOperator
class CrossoverOperator:
    """
    LLM-based harness crossover.

    Reads ``crossover_prompt.txt``, presents both parent harnesses with their
    coverage metrics, and asks the LLM to synthesise an offspring that inherits
    the best traits of each.
    """

    PROMPT_PATH = Path(PROJECT_PATH) / "agent" / "prompts" / "crossover_prompt.txt"

    def __init__(self, llm: BaseChatModel, logger: logging.Logger):
        self.llm    = llm
        self.logger = logger
        self._template = _load_template(self.PROMPT_PATH)

    def crossover(
        self,
        parent1: HarnessGenome,
        parent2: HarnessGenome,
        function_signature: str,
        api_context: str = "",
        project_lang: LanguageType = LanguageType.CPP,
    ) -> str:
        """
        Combine ``parent1`` and ``parent2`` via the LLM.

        Returns offspring C/C++ source code, or the better parent's code if
        the LLM call fails.
        """
        prompt = _fill(
            self._template,
            FUNCTION_SIGNATURE   = function_signature,
            PARENT1_CODE         = parent1.code,
            PARENT2_CODE         = parent2.code,
            PARENT1_COVERAGE     = prompt_value(parent1.fitness.coverage),
            PARENT2_COVERAGE     = prompt_value(parent2.fitness.coverage),
            PARENT1_FEATURES     = prompt_value(parent1.fitness.features),
            PARENT2_FEATURES     = prompt_value(parent2.fitness.features),
            API_CONTEXT          = api_context or "(none)",
            LANGUAGE_NOTE        = _build_language_note(project_lang),
        )

        self.logger.info(
            f"[Crossover] {parent1.genome_id} x {parent2.genome_id}  "
            f"cov=({parent1.fitness.coverage}, {parent2.fitness.coverage})"
        )

        try:
            response  = self.llm.invoke([HumanMessage(content=prompt)])
            offspring = _extract_cpp_code(response.content)
            self.logger.info(
                f"[Crossover] success — output length: {len(offspring)} chars"
            )
            return offspring
        except Exception as exc:
            self.logger.error(f"[Crossover] LLM call failed: {exc}")
            # fallback: return the fitter parent
            fallback = (
                parent1 if parent1.total_fitness() >= parent2.total_fitness()
                else parent2
            )
            self.logger.warning(
                f"[Crossover] using parent {fallback.genome_id} as fallback"
            )
            return fallback.code