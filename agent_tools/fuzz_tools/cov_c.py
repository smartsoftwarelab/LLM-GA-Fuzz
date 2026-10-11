#!/usr/bin/env python3

import subprocess
import argparse
from typing import List, Optional
from pathlib import Path
import json

def kill_process(process):
    try:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    except:
        pass
def reply_corpus(fuzzer_name: str, corpus_path: str, timeout: int = 30) -> Optional[str]:
    """
    Run fuzzer and extract edge coverage.
    """
    process = None
    try:
        # Construct command with optional merge flag
        # -runs=0 means replay all inputs in corpus without additional fuzzing
        cmd = [f"./{fuzzer_name}", "-runs=0", f"-timeout={timeout}"]
        cmd.append(corpus_path)
        
        # Run command and capture output
        process = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout (like 2>&1)
            text=True, 
            timeout=timeout + 5,  # Add extra timeout buffer
            start_new_session=True  # Prevents inheriting Pool's pipes
        )
    except subprocess.TimeoutExpired:
        msg = f"Error: Fuzzer command timed out after {timeout} seconds"
        print(msg)
        kill_process(process)
        return msg
    except Exception as e:
        msg = f"Error: running fuzzer {e}"
        print(msg)
        kill_process(process)
        return msg

def sort_files(directory: Path) -> List[Path]:
    """
    Sort the files in a directory.
    
    Args:
        directory: Path to the directory
    
    Returns:
        List of paths to the oldest files
    """
   
    # Get all files with modification times
    files = [
        (file, file.stat().st_mtime)
        for file in directory.iterdir() 
        if file.is_file()
    ]
    
    # Sort by modification time
    files.sort(key=lambda x: x[1])
    
    return [f[0] for f in files]


def get_function_cov(fuzzer_name: str,  corpus_dir: str) -> tuple[int, int, int, str]:
    """
    Replay corpus and compute edge coverage.

    Returns:
        (init_cov, final_cov, total_edges, message)
        total_edges = size of __sancov_cntrs section = total instrumented edges in binary
    """
    reply_corpus(fuzzer_name, corpus_dir)
    bitmaps_dir = Path("./bitmaps")

    # list all files in bitmaps directory
    if not bitmaps_dir.exists():
        msg = f"Error: Directory does not exist: {bitmaps_dir}"
        return 0, 0, 0, msg

    all_maps = sort_files(bitmaps_dir)
    if len(all_maps) == 0:
        return 0, 0, 0, "Error: No bitmap files found"

    # Read first file as binary and convert to boolean array
    with open(all_maps[0], 'rb') as f:
        first_file_bytes = f.read()
        merged_map = [byte != 0 for byte in first_file_bytes]

    # bitmap length == __stop___sancov_cntrs - __start___sancov_cntrs == total edges
    total_edges = len(first_file_bytes)

    init_cov = 0
    for counter_map_file in all_maps:
        # Read each file as binary and convert to boolean array
        with open(counter_map_file, 'rb') as f:
            current_file_bytes = f.read()
            counter_map = [byte != 0 for byte in current_file_bytes]

        # Count number of True values
        counter_sum = sum(counter_map)

        # only counter once
        if counter_sum != 0 and init_cov == 0:
            init_cov = counter_sum

        # Skip empty counter maps
        if len(counter_map) == 0:
            continue
        # Perform bitwise OR operation manually
        merged_map = [a or b for a, b in zip(merged_map, counter_map)]

    done_cov = sum(merged_map)

    return init_cov, done_cov, total_edges, "Success"


def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Corpus Reduction Fuzzing Script')
    parser.add_argument('--fuzzer-name', default="server_fuzzer", help='Path to fuzzer binary')
    parser.add_argument('--corpus-dir', default="./corpora/", help='Path to corpus directory')
    
    args = parser.parse_args()
    
    # Run corpus reduction
    init_cov, final_cov, total_edges, msg = get_function_cov(
        args.fuzzer_name,
        args.corpus_dir,
    )
    edge_pct = round(final_cov / total_edges * 100, 2) if total_edges > 0 else 0.0
    improvement_pct = round((final_cov - init_cov) / init_cov * 100, 2) if init_cov > 0 else 0.0
    with open("cov.json", "w") as f:
        f.write(json.dumps({
            "init_cov": init_cov,
            "final_cov": final_cov,
            "total_edges": total_edges,
            "edge_pct": edge_pct,
            "improvement_pct": improvement_pct,
            "msg": msg,
        }, indent=4))

if __name__ == '__main__':
    main()