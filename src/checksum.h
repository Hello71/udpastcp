#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

// based on code from RFCs 1071 and 1624

/*
static inline uint16_t csum_update(const void *ptr, uint16_t new_value, uint16_t wsum) {
    uint32_t sum = *(uint16_t *)ptr + (~ntohs(*(uint16_t *)&new_value) & 0xffff) + ntohs(wsum);
    sum = (sum & 0xffff) + (sum >> 16);
    return htons(sum + (sum >> 16));
}

static inline uint16_t fold_sum(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return sum;
}

static inline uint16_t do_csum(const void *ptr, size_t len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += *(uint16_t *)ptr++;
        len -= 2;
    }

    if (len > 0)
        sum += *(uint8_t *)ptr;

    return ~fold_sum(sum);
}

static inline uint16_t csum_partial(uint16_t sum, const void *ptr, size_t len, ...) {
    va_list ap;
    va_start(ap, len);
    do {
        sum = ~fold_sum(~sum + ~do_csum(ptr, len));
    } while ((ptr = va_arg(ap, const void *)) && (len = va_arg(ap, size_t)));
    va_end(ap);
    return sum;
}
*/

uint16_t csum_partial(const void *buff, int len, uint16_t wsum);
