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

#include "wimlib/assert.h"
#include "wimlib/bitops.h"
#include "wimlib/unaligned.h"

#include <smmintrin.h>

/* Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @start_len bytes are matched.  */
static inline machine_word_t
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  const machine_word_t start_len, const machine_word_t max_len)
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

	u64 len = start_len;

	__asm__(
		"1:                                          \n"
		"  movdqu 0x0(%[strptr],%[len],1), %%xmm0    \n"
		"  pcmpestri $0x18, 0x0(%[matchptr],%[len],1), %%xmm0    \n"
		"  jc 2f                                     \n"
		"  add $0x10, %[len]                         \n"

		"  movdqu 0x0(%[strptr],%[len],1), %%xmm0    \n"
		"  pcmpestri $0x18, 0x0(%[matchptr],%[len],1), %%xmm0    \n"
		"  jc 2f                                     \n"
		"  add $0x10, %[len]                         \n"

		"  movdqu 0x0(%[strptr],%[len],1), %%xmm0    \n"
		"  pcmpestri $0x18, 0x0(%[matchptr],%[len],1), %%xmm0    \n"
		"  jc 2f                                     \n"
		"  add $0x10, %[len]                         \n"

		"  cmp $257, %[len]                          \n"
		"  jb 1b                                     \n"
		"  xor %%rcx, %%rcx                          \n"
		"2:                                          \n"
		"  add %%rcx, %[len]                         \n"
		: [len] "+r" (len)
		: "a" (16), "d" (16), [strptr] "r" (strptr), [matchptr] "r" (matchptr)
		: "rcx", "cc", "xmm0", "memory"
	       );


	return min(len, max_len);
#endif
}

#endif /* _WIMLIB_LZ_EXTEND_H */
