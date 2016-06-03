/*
 * lz_extend.h - fast match extension for Lempel-Ziv matchfinding
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2014-2015 by Eric Biggers <ebiggers3@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide via the Creative Commons Zero 1.0 Universal Public Domain
 * Dedication (the "CC0").
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the CC0 for more details.
 *
 * You should have received a copy of the CC0 along with this software; if not
 * see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _WIMLIB_LZ_EXTEND_H
#define _WIMLIB_LZ_EXTEND_H

#include "wimlib/bitops.h"
#include "wimlib/unaligned.h"

#include <smmintrin.h>

/* Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @start_len bytes are matched.  */
static inline u32
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  const u32 start_len, const u32 max_len)
{
#if 0
	u32 len = start_len;
	machine_word_t v_word;

	for (;;) {
		v_word = load_word_unaligned(&matchptr[len]) ^
			 load_word_unaligned(&strptr[len]);
		if (v_word != 0 || len >= max_len)
			break;
		len += WORDSIZE;
	}

	return min(max_len, len + (ffsw(v_word) >> 3));
#else

	const u8 *p1 = strptr + start_len;
	const u8 *p2 = matchptr + start_len;

	u8 saved = strptr[max_len];
	((u8 *)strptr)[max_len] = matchptr[max_len] + 1;

	__asm__(
		"  movdqu (%[p1]), %%xmm0                    \n"
		"  pcmpestri $0x18, (%[p2]), %%xmm0          \n"
		"  jc 2f                                     \n"
		"1:                                          \n"
		"  add $0x10, %[p1]                          \n"
		"  add $0x10, %[p2]                          \n"
		"  movdqu (%[p1]), %%xmm0                    \n"
		"  pcmpestri $0x18, (%[p2]), %%xmm0          \n"
		"  jnc 1b                                    \n"
		"2:                                          \n"
		"  add %%rcx, %[p1]                          \n"
		"  add %%rcx, %[p2]                          \n"
		: [p1] "+r" (p1), [p2] "+r" (p2)
		: "a" (16), "d" (16)
		: "rcx", "cc", "xmm0", "memory"
	       );


	((u8 *)strptr)[max_len] = saved;

	return p1 - strptr;
#endif
}

#endif /* _WIMLIB_LZ_EXTEND_H */
