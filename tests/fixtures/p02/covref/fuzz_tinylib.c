#include <stddef.h>
#include <stdint.h>

#include "tinylib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    classify(data, size);
    return 0;
}
