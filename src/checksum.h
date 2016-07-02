#include <stdint.h>

static inline uint16_t do_csum(const char *buf, unsigned size) {
    unsigned int sum = 0;
    unsigned int i;

    for (i = 0; i < size - 1; i += 2)
        sum += *(uint16_t *)&buf[i];

    if (size & 1)
        sum += (uint8_t)buf[i];

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static inline uint16_t csum_partial(const void *buff, int len, uint16_t wsum) {
    unsigned int sum = (unsigned int)wsum;
    unsigned int result = do_csum(buff, len);

    result += sum;
    if (sum > result)
        result += 1;
    return result;
}
