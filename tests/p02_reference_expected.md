# PATCH 2 reference: hand-derived llvm-cov numbers for `tinylib.c`

Measured unit (config `coverage_metric: branches`): llvm-cov **branch** coverage of
source-based coverage builds (OSS-Fuzz `--sanitizer=coverage`, i.e. clang
`-fprofile-instr-generate -fcoverage-mapping`). For every boolean condition in an
`if`, llvm-cov counts two branches: the True outcome and the False outcome. A
branch is covered when its outcome occurred at least once.

Scope: files under `/src/llmga-covref/` (derived from the harness path
`/src/llmga-covref/fuzz_tinylib.c`), minus the harness file itself, so only
`/src/llmga-covref/tinylib.c` counts.

`tinylib.c` has three conditions and no `&&`, `||`, `?:`, loops or `switch`:

| id | condition       | reached when      |
|----|-----------------|-------------------|
| C1 | `size < 2`      | always            |
| C2 | `data[0]=='A'`  | size >= 2         |
| C3 | `data[1]=='B'`  | size >= 2, d0='A' |

Total branches = 3 conditions x 2 outcomes = **6**. Functions in scope = 1 (`classify`).

| input  | C1 | C2 | C3 | outcomes hit |
|--------|----|----|----|--------------|
| ""     | T  | -  | -  | C1T |
| "AB"   | F  | T  | T  | C1F C2T C3T |
| "AC"   | F  | T  | F  | C1F C2T C3F |
| "ZZ"   | F  | F  | -  | C1F C2F |

| corpus | inputs               | covered branches (union) | expected |
|--------|----------------------|--------------------------|----------|
| A      | "", "AB"             | C1T C1F C2T C3T          | **4 / 6**, functions 1/1 |
| B      | "", "AB", "AC", "ZZ" | all six                  | **6 / 6**, functions 1/1 |
| C      | "AB"                 | C1F C2T C3T              | **3 / 6**, functions 1/1 |

Corpora A and B contain the empty input on purpose: if the fuzzer binary executed
an extra empty input on its own, A and B would not change. Corpus C has no empty
input and therefore tests the assumption that `./fuzz_tinylib <file>` executes only
that file. A result of 4/6 for C would falsify that assumption (not the pipeline's
counting) and must be reported, not adjusted.

Determinism gate: corpus A is measured three times in fresh builds; status,
covered, total and every scoped metric must be identical.
