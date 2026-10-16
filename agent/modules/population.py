from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from agent.modules.fitness import FitnessScores


# Operation labels (how a genome was created)
OP_INITIAL    = "INITIAL"
OP_CACHED     = "INITIAL_CACHED"
OP_MUTATION   = "MUTATION"
OP_CROSSOVER  = "CROSSOVER"
OP_REPAIR     = "REPAIR"


# HarnessGenome

@dataclass
class HarnessGenome:
    """
    One individual in the evolutionary population.

    ``code``    : the C/C++ harness source
    ``fitness`` : populated after compilation + short fuzz trial
    """

    genome_id:  str
    code:       str
    generation: int
    parent_ids: List[str]
    operation:  str                          # one of OP_* constants above

    fitness:       FitnessScores = field(default_factory=FitnessScores)
    compile_ok:    bool          = False
    compile_error: str           = ""
    fuzz_log_path: Optional[str] = None

    
    # Factory helpers
    

    @staticmethod
    def new_id() -> str:
        """Generate a short unique identifier."""
        return uuid.uuid4().hex[:12]

    @classmethod
    def make(
        cls,
        code: str,
        generation: int,
        parent_ids: List[str],
        operation: str,
    ) -> "HarnessGenome":
        return cls(
            genome_id=cls.new_id(),
            code=code,
            generation=generation,
            parent_ids=parent_ids,
            operation=operation,
        )

    
    # Scoring
    

    def total_fitness(self) -> float:
        return self.fitness.total()

    def feature_hash(self) -> str:
        """
        Structural fingerprint of the harness code.
        Used for novelty / diversity detection in the archive.
        """
        return hashlib.md5(self.code.encode("utf-8", errors="ignore")).hexdigest()

    
    # Serialisation
    

    def to_dict(self) -> dict:
        return {
            "genome_id":    self.genome_id,
            "code":         self.code,
            "generation":   self.generation,
            "parent_ids":   self.parent_ids,
            "operation":    self.operation,
            "compile_ok":   self.compile_ok,
            "compile_error": self.compile_error,
            "fuzz_log_path": self.fuzz_log_path,
            "fitness": {
                "status":        self.fitness.status,
                "error_message": self.fitness.error_message,
                "coverage":     self.fitness.coverage,
                "features":     self.fitness.features,
                "exec_per_sec": self.fitness.exec_per_sec,
                "stability":    self.fitness.stability,
                "crash_found":  self.fitness.crash_found,
                "crash_events":   self.fitness.crash_events,
                "library_crash":  self.fitness.library_crash,
                "crash_location": self.fitness.crash_location,
                "discard_reason": self.fitness.discard_reason,
                "compile_ok":   self.fitness.compile_ok,
                "total":        self.fitness.total(),
            },
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            f"HarnessGenome(id={self.genome_id}, gen={self.generation}, "
            f"op={self.operation}, compiled={self.compile_ok}, "
            f"fitness={self.total_fitness():.4f})"
        )


# Archive

class Archive:
    """
    Diversity-preserving archive of the best harness genomes.

    Selection policy:
    - Elite half  : strictly highest fitness
    - Diverse half: harnesses with unique feature_hash values not in elite set
    This guards against premature convergence (all genomes look the same).
    """

    def __init__(self, capacity: int = 20):
        self.capacity = capacity
        self._genomes: List[HarnessGenome] = []

    
    # Insertion
    

    def add(self, genome: HarnessGenome) -> None:
        """Add a genome to the archive (only compiled genomes accepted)."""
        if not genome.compile_ok:
            return
        self._genomes.append(genome)
        if len(self._genomes) > self.capacity * 2:   # prune lazily
            self._prune()

    def update(self, genomes: List[HarnessGenome]) -> None:
        """Add multiple genomes, then prune once."""
        for g in genomes:
            if g.compile_ok:
                self._genomes.append(g)
        self._prune()

    def _prune(self) -> None:
        """Reduce archive to ``capacity`` genomes using elite + diversity."""
        if len(self._genomes) <= self.capacity:
            return

        # sort by fitness descending
        self._genomes.sort(key=lambda g: g.total_fitness(), reverse=True)

        elite_size  = self.capacity // 2
        elite       = self._genomes[:elite_size]
        rest        = self._genomes[elite_size:]

        seen_hashes = {g.feature_hash() for g in elite}
        diverse: List[HarnessGenome] = []
        duplicates: List[HarnessGenome] = []

        for g in rest:
            h = g.feature_hash()
            if h not in seen_hashes:
                seen_hashes.add(h)
                diverse.append(g)
            else:
                duplicates.append(g)

        # fill remaining slots: prefer diverse, then duplicates (by fitness)
        slots_left  = self.capacity - len(elite)
        combined    = diverse[:slots_left]
        if len(combined) < slots_left:
            combined += duplicates[: slots_left - len(combined)]

        self._genomes = elite + combined

    
    # Retrieval
    

    def best(self, n: int = 1) -> List[HarnessGenome]:
        """Return the top-n genomes by fitness (compiled only)."""
        valid = [g for g in self._genomes if g.compile_ok]
        valid.sort(key=lambda g: g.total_fitness(), reverse=True)
        return valid[:n]

    def all_valid(self) -> List[HarnessGenome]:
        return [g for g in self._genomes if g.compile_ok]

    
    # Selection (for genetic operators)
    

    def tournament_select(self, k: int = 3) -> HarnessGenome:
        """
        Tournament selection: pick k candidates at random, return the best.
        Prefers compiled genomes; falls back to any genome if needed.
        """
        valid = self.all_valid()
        pool  = valid if valid else self._genomes
        if not pool:
            raise ValueError("Archive is empty; cannot select.")
        candidates = random.sample(pool, min(k, len(pool)))
        return max(candidates, key=lambda g: g.total_fitness())

    def select_pair(self, k: int = 3) -> tuple:
        """
        Select two distinct parents via tournament selection.
        Returns (parent1, parent2).
        """
        p1 = self.tournament_select(k)
        p2 = self.tournament_select(k)
        for _ in range(5):          # retry to avoid selecting the same genome
            if p2.genome_id != p1.genome_id:
                break
            p2 = self.tournament_select(k)
        return p1, p2

    
    # Introspection
    

    def __len__(self) -> int:
        return len(self._genomes)

    def coverage_stats(self) -> dict:
        # only genomes with measured statistics; failed trials are not counted as 0
        covs = [g.fitness.coverage for g in self.all_valid() if g.fitness.coverage is not None]
        if not covs:
            return {"max": None, "mean": None, "min": None}
        return {
            "max":  max(covs),
            "mean": sum(covs) / len(covs),
            "min":  min(covs),
        }

    def __repr__(self) -> str:
        stats = self.coverage_stats()
        mean = "None" if stats["mean"] is None else f"{stats['mean']:.1f}"
        return (
            f"Archive(size={len(self._genomes)}/{self.capacity}, "
            f"cov_max={stats['max']}, cov_mean={mean})"
        )
