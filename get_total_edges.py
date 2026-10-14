#!/usr/bin/env python3
"""
get_total_edges.py  —  برای استفاده داخل OSS-Fuzz Docker
---------------------------------------------------------
تعداد کل یال‌های instrumented را از باینری فازر استخراج می‌کند.
از section __sancov_cntrs در ELF باینری استفاده می‌کند.

فرمول:  Coverage% = (cov= از libFuzzer log) / total_edges * 100

نحوه استفاده:
  # داخل Docker (بعد از compile):
  python3 get_total_edges.py --binary /out/<fuzzer_name>
  
  # یا با one-liner:
  python3 -c "
  import subprocess
  out = subprocess.check_output(['nm','-n','/out/<fuzzer_name>'], text=True)
  lines = out.splitlines()
  addrs = {}
  for l in lines:
      if '__start___sancov_cntrs' in l: addrs['start'] = int(l.split()[0],16)
      if '__stop___sancov_cntrs'  in l: addrs['stop']  = int(l.split()[0],16)
  print('Total edges:', addrs['stop'] - addrs['start'])
  "

اهداف و نام فازر در OSS-Fuzz (از fuzzer_info.json):
  ada-url   -> /out/ada_c
  freerdp   -> /out/TestFuzzCryptoCertificateDataSetPEM  (نام در output.log)
  cjson     -> /out/cjson_read_fuzzer

نتیجه coverage% برای هر هدف:
  Coverage% = best_cov (از evo_results.json) / total_edges * 100
"""

import subprocess, sys, re, argparse, json
from pathlib import Path


def get_total_edges(binary_path: str) -> int:
    """Extract total edges using nm (start/stop address difference)."""
    try:
        out = subprocess.check_output(
            ["nm", "-n", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        start_addr = stop_addr = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                if "__start___sancov_cntrs" in parts[-1]:
                    start_addr = int(parts[0], 16)
                if "__stop___sancov_cntrs" in parts[-1]:
                    stop_addr  = int(parts[0], 16)
        if start_addr is not None and stop_addr is not None:
            return stop_addr - start_addr
    except Exception:
        pass

    # Fallback: readelf
    try:
        out = subprocess.check_output(
            ["readelf", "-S", "--wide", binary_path],
            stderr=subprocess.DEVNULL, text=True
        )
        match = re.search(
            r'__sancov_cntrs\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)',
            out
        )
        if match:
            return int(match.group(1), 16)
    except Exception:
        pass

    return 0


def compute_coverage_percent(covered_edges: int, total_edges: int) -> float:
    if total_edges == 0:
        return 0.0
    return covered_edges / total_edges * 100.0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract total edge count from OSS-Fuzz fuzzer binary"
    )
    parser.add_argument("--binary", required=True, help="Path to compiled fuzzer binary")
    parser.add_argument("--covered", type=int, default=0,
                        help="Covered edges (cov= value from libFuzzer log) to compute %")
    args = parser.parse_args()

    total = get_total_edges(args.binary)
    if total == 0:
        print("ERROR: Could not determine total edge count from binary.")
        print("Make sure the binary was compiled with -fsanitize-coverage=edge,trace-pc-guard")
        sys.exit(1)

    print(f"\nBinary          : {args.binary}")
    print(f"Total edges     : {total:,}")

    if args.covered > 0:
        pct = compute_coverage_percent(args.covered, total)
        print(f"Covered edges   : {args.covered:,}")
        print(f"Edge Coverage%  : {pct:.2f}%")

    # If an evo_results.json is nearby, compute for all targets
    results_file = Path("evo_results.json")
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)
        print("\n--- Coverage% from evo_results.json ---")
        for key, val in data.items():
            best_cov = val.get("best_coverage")
            if best_cov is None:
                print(f"  {val['function'][:60]}: no measured coverage")
                continue
            pct = compute_coverage_percent(best_cov, total)
            print(f"  {val['function'][:60]}: {best_cov} edges = {pct:.2f}%")
