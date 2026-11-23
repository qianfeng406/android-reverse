#include <stdint.h>

__attribute__((visibility("default"), noinline))
int32_t route_score(int32_t input) {
    uint32_t value = (uint32_t)input;
    uint32_t score = 17;

    if (input < 0)
        value = ~value + 1u;

    for (uint32_t i = 0; i < 6; ++i) {
        if ((value & 3u) == 0)
            score += value + i;
        else if ((value & 1u) == 0)
            score ^= value + 19u;
        else
            score += (value ^ i) & 31u;

        if ((score & 8u) != 0)
            value = (value >> 1) + i;
        else
            value = (value >> 2) ^ (i + 3u);

        if (i == 3 && (score & 128u) != 0)
            score -= 7u;
    }

    for (uint32_t j = 0; j < 3; ++j) {
        if ((score & 1u) != 0)
            score = (score << 1) ^ (value + j);
        else
            score += (value >> j) + j;
    }

    if (score > 200u)
        return (int32_t)(score ^ 90u);
    if (score < 50u)
        return (int32_t)(score + 11u);
    return (int32_t)(score * 3u + 1u);
}
