FROM gcr.io/oss-fuzz-base/base-builder
RUN mkdir -p $SRC/llmga-covref
COPY tinylib.c tinylib.h fuzz_tinylib.c $SRC/llmga-covref/
WORKDIR $SRC/llmga-covref
COPY build.sh $SRC/
