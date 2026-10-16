"""PATCH 4: re-classify crash events in existing logs (old rule vs new rule).

Old rule (pre-PATCH 4): a trial got the crash bonus if its log contained any of
"ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "ERROR: libFuzzer:", "== Java Exception",
"SUMMARY: AddressSanitizer".
New rule: libFuzzer errors (oom, timeout, deadly signal, const-input overwrite, other) and
leaks are harness failures (no bonus); sanitizer reports are library crashes only if a stack
frame lies in the library source tree. Logs without stack frames (all -fork=1 trials) cannot
be located from the log alone and are reported as 'location unknown'.

Usage: python scripts/p04_reclassify_logs.py <dir> [<dir> ...] [--glob '*.log']
"""
import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.modules.fitness import HARNESS_FAILURE_TYPES, classify_events  # noqa: E402

OLD_MARKERS = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "ERROR: libFuzzer:",
               "== Java Exception", "SUMMARY: AddressSanitizer")
FRAME = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+.+?\s+/\S+?:\d+", re.MULTILINE)

ap = argparse.ArgumentParser()
ap.add_argument("dirs", nargs="+")
ap.add_argument("--glob", default="*.log")
args = ap.parse_args()

files = [p for d in args.dirs for p in Path(d).rglob(args.glob) if p.is_file()]
events_total: Counter = Counter()
old_bonus = 0
new_classes: Counter = Counter()
for f in files:
    text = f.read_text(encoding="utf-8", errors="ignore")
    ev = classify_events(text)
    events_total.update(ev)
    if any(m in text for m in OLD_MARKERS):
        old_bonus += 1
    if not ev:
        continue
    if "sanitizer" in ev:
        new_classes["sanitizer crash, stack in log (location decidable)" if FRAME.search(text)
                    else "sanitizer crash, no stack in log (location unknown -> no bonus until reproduced)"] += 1
    elif all(t in HARNESS_FAILURE_TYPES for t in ev):
        new_classes["harness failure only (no bonus)"] += 1

print(f"files scanned: {len(files)}  (dirs: {', '.join(args.dirs)}, glob: {args.glob})")
print(f"OLD rule - files that earned the crash bonus: {old_bonus}")
print("NEW rule - files by class:")
for k, v in sorted(new_classes.items()):
    print(f"  {v:5d}  {k}")
print("event counts by type (all files):")
for k, v in sorted(events_total.items()):
    print(f"  {v:6d}  {k}{'  [harness failure]' if k in HARNESS_FAILURE_TYPES else ''}")
