#!/bin/bash
# PATCH 2 acceptance: llvm-cov pipeline vs. hand-derived reference
# (tests/p02_reference_expected.md). Needs Docker + oss-fuzz checkout.
# Usage: bash scripts/p02_coverage_reference.sh [out_dir]
set -euo pipefail
CODE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OSSFUZZ_DIR="${OSSFUZZ_DIR:-/home/ubuntu/fuzzing_workspace/oss-fuzz}"
OUT="${1:-/tmp/p02_reference}"
PROJ=llmga-covref

rm -rf "$OUT"
mkdir -p "$OUT/corpus_A" "$OUT/corpus_B" "$OUT/corpus_C"
: > "$OUT/corpus_A/c0_empty";  printf 'AB' > "$OUT/corpus_A/c1_AB"
cp "$OUT/corpus_A/"* "$OUT/corpus_B/"
printf 'AC' > "$OUT/corpus_B/c2_AC"; printf 'ZZ' > "$OUT/corpus_B/c3_ZZ"
printf 'AB' > "$OUT/corpus_C/c1_AB"

run() {  # <label> <corpus letter>: fresh project copy, fresh image + coverage build
    rm -rf "$OSSFUZZ_DIR/projects/$PROJ"
    cp -r "$CODE_DIR/tests/fixtures/p02/covref" "$OSSFUZZ_DIR/projects/$PROJ"
    python "$CODE_DIR/tests/p02_reference_driver.py" --oss-fuzz-dir "$OSSFUZZ_DIR" \
        --corpus "$OUT/corpus_$2" --out "$OUT/$1" 2>&1 | tail -1
}
run A1 A; run A2 A; run A3 A; run B1 B; run C1 C

python - "$OUT" <<'EOF'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
r = {k: json.loads((out / k / "result.json").read_text()) for k in ["A1", "A2", "A3", "B1", "C1"]}
def key(x): return (x["status"], x["covered"], x["total"], json.dumps(x["metrics"].get("scope"), sort_keys=True))
checks = [
    ("A determinism (A1 == A2 == A3)", key(r["A1"]) == key(r["A2"]) == key(r["A3"])),
    ("A branches == 4/6", (r["A1"]["status"], r["A1"]["covered"], r["A1"]["total"]) == ("OK", 4, 6)),
    ("B branches == 6/6", (r["B1"]["status"], r["B1"]["covered"], r["B1"]["total"]) == ("OK", 6, 6)),
    ("C branches == 3/6", (r["C1"]["status"], r["C1"]["covered"], r["C1"]["total"]) == ("OK", 3, 6)),
    ("functions 1/1 in A, B, C", all(r[k]["metrics"]["scope"]["functions"] == {"covered": 1, "count": 1} for k in ["A1", "B1", "C1"])),
    ("harness excluded, tinylib.c in scope", all(r[k]["metrics"]["files_in_scope"] == ["/src/llmga-covref/tinylib.c"] for k in ["A1", "B1", "C1"])),
]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
print("OVERALL:", "PASS" if all(ok for _, ok in checks) else "FAIL")
print("tool versions:", (out / "A1" / "raw" / "tool_versions.txt").read_text().strip().replace("\n", " | ")[:300])
EOF
