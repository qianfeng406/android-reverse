#include <stdint.h>

/* Keep this exported function small enough to inspect in the generated .so. */
__attribute__((visibility("default"), noinline))
int32_t lesson_score(int32_t input) {
    int32_t value = input;

    if (value < 0) {
        value = -value;
    }

    int32_t score = 0;
    for (int32_t i = 0; i < 4; ++i) {
        if ((value & 1) == 0) {
            score += value + i;
        } else {
            score += value - i;
        }
        value >>= 1;
    }

    if (score > 20) {
        return score ^ 0x5a;
    }
    return score + 7;
}
