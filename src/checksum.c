/*
 *
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *		Andreas Schwab, <schwab@issan.informatik.uni-dortmund.de>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * 03/02/96	Jes Sorensen, Andreas Schwab, Roman Hodek:
 *		Fixed some nasty bugs, causing some horrible crashes.
 *		A: At some points, the sum (%0) was used as
 *		length-counter instead of the length counter
 *		(%1). Thanks to Roman Hodek for pointing this out.
 *		B: GCC seems to mess up if one uses too many
 *		data-registers to hold input values and one tries to
 *		specify d0 and d1 as scratch registers. Letting gcc
 *		choose these registers itself solves the problem.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/* Based on code from the Linux kernel. */

#include <assert.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "checksum.h"

/* Revised by Kenneth Albanowski for m68knommu. Basic problem: unaligned access
 kills, so most of the assembly has to go. */

static inline uint16_t from32to16(uint32_t x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return (uint16_t)x;
}

static uint16_t do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += ((unsigned int)(*buff) << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
        assert(!((unsigned long)buff & 1));
	if (len >= 2) {
		if (2 & (const unsigned long) buff) {
			result += *(const unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
                assert(!((unsigned long)buff & 2));
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3u);
			unsigned int carry = 0;
			do {
				unsigned int w = *(const unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(const unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return (uint16_t)result;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
uint16_t csum_partial(const void *buff, int len, uint16_t wsum)
{
	uint16_t sum = wsum;
	uint16_t result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return result;
}

uint16_t csum_sockaddr_partial(const struct sockaddr *addr, int incl_port, uint16_t wsum)
{
    if (incl_port)
        wsum = csum_partial(&((struct sockaddr_in *)addr)->sin_port, sizeof(in_port_t), wsum);

    switch (addr->sa_family) {
    case AF_INET:
        return csum_partial(&((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr), wsum);
    case AF_INET6:
        return csum_partial(&((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr), wsum);
    default:
        abort();
    }
}
