"""run_manifest.json: everything needed to reconstruct one run (one target, one repetition).

All environment facts are collected at runtime (git, docker); nothing is hard-coded.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

BASE_IMAGES = ("gcr.io/oss-fuzz-base/base-builder", "gcr.io/oss-fuzz-base/base-runner")
# Fields that legitimately differ between repetitions of the same experiment.
_RUN_VARYING = ("seed", "repetition_index", "save_root")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def derive_seed(base_seed: int, target_id: str) -> int:
    """Per-target seed: stable across machines and Python processes."""
    return int(hashlib.sha256(f"{base_seed}:{target_id}".encode()).hexdigest()[:8], 16)


def config_hash(snapshot: dict[str, Any]) -> str:
    """sha256 of the redacted config without run-varying fields (seed, repetition, save_root)."""
    def strip(d: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in d.items() if k not in _RUN_VARYING}
    stable = strip(snapshot)
    if isinstance(stable.get("config"), dict):
        stable["config"] = strip(stable["config"])
    return hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()


def git_info(path: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True,
                              check=True, timeout=30).stdout.strip()
    try:
        porcelain = git("status", "--porcelain")
        return {"commit": git("rev-parse", "HEAD"), "dirty": bool(porcelain),
                "n_changed_paths": len(porcelain.splitlines()) if porcelain else 0}
    except Exception as exc:
        return {"commit": None, "dirty": None, "error": f"{type(exc).__name__}: {exc}"}


def docker_image_info(names: tuple[str, ...] = BASE_IMAGES) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        import docker
        client = docker.from_env()
    except Exception as exc:
        return {n: {"error": f"{type(exc).__name__}: {exc}"} for n in names}
    for name in names:
        try:
            image = client.images.get(name)
            out[name] = {"id": image.id, "repo_digests": image.attrs.get("RepoDigests", []),
                         "created": image.attrs.get("Created")}
        except Exception as exc:
            out[name] = {"id": None, "repo_digests": [], "error": f"{type(exc).__name__}: {exc}"}
    return out


class RunManifest:
    """Incrementally written manifest; rewritten after every update so a crash leaves a record."""

    def __init__(self, path: Path, **fields: Any) -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = {"status": "running", "start_time": now_iso(), "end_time": None,
                                     "phases": {}, **fields}
        self.write()

    def update(self, **fields: Any) -> None:
        self.data.update(fields)
        self.write()

    @contextlib.contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Record wall-clock start/end/seconds of a pipeline phase."""
        entry: dict[str, Any] = {"start": now_iso(), "end": None, "seconds": None}
        self.data["phases"][name] = entry
        t0 = time.monotonic()
        try:
            yield
        finally:
            entry["end"] = now_iso()
            entry["seconds"] = round(time.monotonic() - t0, 3)
            self.write()

    def finish(self, status: str, **fields: Any) -> None:
        self.data.update(status=status, end_time=now_iso(), **fields)
        self.write()

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2, default=str))
        tmp.replace(self.path)


def load_manifest(path: Path) -> Optional[dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None
