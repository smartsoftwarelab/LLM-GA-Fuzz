#include "tinylib.h"

/* Three independent conditions, no && / || / ?: / loops / switch.
 * llvm-cov branch coverage counts a True and a False outcome per condition,
 * so this file has exactly 3 x 2 = 6 branches (see tests/p02_reference_expected.md). */
int classify(const uint8_t *data, size_t size) {
    if (size < 2) {            /* C1 */
        return 0;
    }
    if (data[0] == 'A') {      /* C2 */
        if (data[1] == 'B') {  /* C3 */
            return 3;
        }
        return 2;
    }
    return 1;
}
