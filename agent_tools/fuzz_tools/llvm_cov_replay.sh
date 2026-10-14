#!/bin/bash
# Replay every corpus input once in an OSS-Fuzz `--sanitizer=coverage` build
# (-fprofile-instr-generate -fcoverage-mapping) and export an llvm-cov summary.
# Runs inside the project image with /out (build output) and /corpus (read-only) mounted.
# Usage: llvm_cov_replay.sh <fuzzer_name> <per_input_timeout_seconds>
# The caller reads the LLMGA_COV_DONE / LLMGA_COV_ERROR marker from stdout.
set -u
FUZZER="/out/$1"
T="$2"
W=/out/llmga_cov

rm -rf "$W"
mkdir -p "$W/profraw"
{ llvm-cov --version; llvm-profdata --version; } > "$W/tool_versions.txt" 2>&1
: > "$W/replay.tsv"
: > "$W/replay.log"

# One process per input, in byte order of file names: a crashing or hanging
# input cannot hide the coverage of the others, and the order is reproducible.
i=0
while IFS= read -r name; do
    [ -f "/corpus/$name" ] || continue
    i=$((i + 1))
    echo "=== [$i] $name" >> "$W/replay.log"
    LLVM_PROFILE_FILE="$W/profraw/$i.profraw" timeout -s KILL "$T" "$FUZZER" "/corpus/$name" >> "$W/replay.log" 2>&1
    printf '%s\t%s\n' "$name" "$?" >> "$W/replay.tsv"
done < <(ls -1A /corpus | LC_ALL=C sort)

ls "$W"/profraw/*.profraw > "$W/profraw.list" 2>/dev/null
if [ ! -s "$W/profraw.list" ]; then
    echo "LLMGA_COV_ERROR no_profraw inputs=$i"
    exit 2
fi
if ! llvm-profdata merge -sparse -f "$W/profraw.list" -o "$W/merged.profdata" > "$W/merge.log" 2>&1; then
    echo "LLMGA_COV_ERROR profdata_merge inputs=$i"
    exit 3
fi
if ! llvm-cov export -summary-only -instr-profile="$W/merged.profdata" "$FUZZER" > "$W/export.json" 2> "$W/export.err"; then
    echo "LLMGA_COV_ERROR llvm_cov_export inputs=$i"
    exit 4
fi
echo "LLMGA_COV_DONE inputs=$i"
