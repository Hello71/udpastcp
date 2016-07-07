#include <stdint.h>

struct sockaddr;

/* calculates the checksum of len bytes at buff when combined with wsum.
 * return value is already in network order, but must be inverted before
 * sending.
 * example: hdr.th_sum = csum_partial(data, len, csum_partial(hdr, hdrlen, 0));
 */
uint16_t csum_partial(const void *buff, int len, uint16_t wsum);

/* calculates the checksum of a sockaddr_in or sockaddr_in6.
 * if incl_port is set then the sin_port will be included.
 * otherwise identical to csum_partial.
 */
uint16_t csum_sockaddr_partial(const struct sockaddr *addr, int incl_port, uint16_t wsum);
