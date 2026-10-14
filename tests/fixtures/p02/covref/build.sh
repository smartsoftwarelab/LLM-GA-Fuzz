#!/bin/bash -eu
# Absolute source paths so llvm-cov reports /src/llmga-covref/... file names.
$CC $CFLAGS -c $SRC/llmga-covref/tinylib.c -o $WORK/tinylib.o
$CC $CFLAGS -c $SRC/llmga-covref/fuzz_tinylib.c -o $WORK/fuzz_tinylib.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzz_tinylib.o $WORK/tinylib.o -o $OUT/fuzz_tinylib
