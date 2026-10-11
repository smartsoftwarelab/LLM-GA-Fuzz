#!/usr/bin/env python3
"""
Coverage collection script for Java fuzzers (Jazzer) in OSS-Fuzz.
This script replays corpus inputs and collects coverage data from bitmaps directory.
"""

import subprocess
import argparse
from typing import List, Optional
from pathlib import Path
import json
import os
import glob


def kill_process(process):
    try:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    except:
        pass


def find_jazzer_driver() -> Optional[str]:
    """Find the Jazzer driver in the current directory."""
    # Look for jazzer_driver or similar
    for pattern in ["jazzer_driver*", "Jazzer*"]:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def replay_corpus_java(fuzzer_name: str, corpus_path: str, timeout: int = 60) -> Optional[str]:
    """
    Run Java fuzzer to replay corpus and generate coverage data.
    For Jazzer, the fuzzer is typically a shell script or JAR file.
    """
    process = None
    try:
        # Check if fuzzer exists
        fuzzer_path = f"./{fuzzer_name}"
        if not os.path.exists(fuzzer_path):
            # Try with _deploy.jar suffix for Bazel-built fuzzers
            jar_path = f"./{fuzzer_name}_deploy.jar"
            if os.path.exists(jar_path):
                # Run with java -jar
                cmd = ["java", "-jar", jar_path, "-runs=0", f"-timeout={timeout}", corpus_path]
            else:
                return f"Error: Fuzzer {fuzzer_name} not found"
        else:
            # Run the fuzzer script/binary directly
            cmd = [fuzzer_path, "-runs=0", f"-timeout={timeout}", corpus_path]
        
        # Run command and capture output
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 30,  # Extra buffer for Java startup
            start_new_session=True
        )
        return None
        
    except subprocess.TimeoutExpired:
        msg = f"Error: Fuzzer command timed out after {timeout} seconds"
        print(msg)
        kill_process(process)
        return msg
    except Exception as e:
        msg = f"Error running Java fuzzer: {e}"
        print(msg)
        kill_process(process)
        return msg


def sort_files(directory: Path) -> List[Path]:
    """
    Sort the files in a directory by modification time.
    """
    files = [
        (file, file.stat().st_mtime)
        for file in directory.iterdir()
        if file.is_file()
    ]
    files.sort(key=lambda x: x[1])
    return [f[0] for f in files]


def get_function_cov(fuzzer_name: str, corpus_dir: str) -> tuple[int, int, int, str]:
    """
    Replay corpus and collect coverage from bitmaps.

    Returns:
        (init_cov, final_cov, total_edges, message)
        total_edges = bitmap size = total instrumented edges in binary
    """
    error = replay_corpus_java(fuzzer_name, corpus_dir)
    if error:
        return 0, 0, 0, error

    bitmaps_dir = Path("./bitmaps")

    if not bitmaps_dir.exists():
        msg = f"Error: Bitmaps directory does not exist: {bitmaps_dir}"
        return 0, 0, 0, msg

    all_maps = sort_files(bitmaps_dir)
    if len(all_maps) == 0:
        return 0, 0, 0, "Error: No bitmap files found"

    # Read first file as binary and convert to boolean array
    with open(all_maps[0], 'rb') as f:
        first_file_bytes = f.read()
        merged_map = [byte != 0 for byte in first_file_bytes]

    # bitmap length == total instrumented edges
    total_edges = len(first_file_bytes)

    init_cov = 0
    for counter_map_file in all_maps:
        with open(counter_map_file, 'rb') as f:
            current_file_bytes = f.read()
            counter_map = [byte != 0 for byte in current_file_bytes]

        counter_sum = sum(counter_map)

        if counter_sum != 0 and init_cov == 0:
            init_cov = counter_sum

        if len(counter_map) == 0:
            continue

        # Perform bitwise OR to merge coverage
        if len(merged_map) == len(counter_map):
            merged_map = [a or b for a, b in zip(merged_map, counter_map)]
        else:
            min_len = min(len(merged_map), len(counter_map))
            merged_map = [merged_map[i] or counter_map[i] for i in range(min_len)]

    done_cov = sum(merged_map)

    return init_cov, done_cov, total_edges, "Success"


def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Java Corpus Coverage Collection Script')
    parser.add_argument('--fuzzer-name', required=True, help='Name of the fuzzer')
    parser.add_argument('--corpus-dir', default="./corpora/", help='Path to corpus directory')
    
    args = parser.parse_args()
    
    init_cov, final_cov, total_edges, msg = get_function_cov(
        args.fuzzer_name,
        args.corpus_dir,
    )
    edge_pct = round(final_cov / total_edges * 100, 2) if total_edges > 0 else 0.0
    improvement_pct = round((final_cov - init_cov) / init_cov * 100, 2) if init_cov > 0 else 0.0
    with open("cov.json", "w") as f:
        json.dump({
            "init_cov": init_cov,
            "final_cov": final_cov,
            "total_edges": total_edges,
            "edge_pct": edge_pct,
            "improvement_pct": improvement_pct,
            "msg": msg,
        }, f, indent=4)


if __name__ == '__main__':
    main()