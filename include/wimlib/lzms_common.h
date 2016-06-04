/*
 * lzms_common.h
 *
 * Declarations shared between LZMS compression and decompression.
 */

#ifndef _LZMS_COMMON_H
#define _LZMS_COMMON_H

#include "wimlib/compiler.h"
#include "wimlib/lzms_constants.h"
#include "wimlib/types.h"

#ifdef __SSE2__
#  include <emmintrin.h>
#endif

#ifdef __AVX2__
#  include <immintrin.h>
#endif


/* Offset slot tables  */
extern const u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];
extern const u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS];

/* Length slot tables  */
extern const u32 lzms_length_slot_base[LZMS_NUM_LENGTH_SYMS + 1];
extern const u8 lzms_extra_length_bits[LZMS_NUM_LENGTH_SYMS];

extern unsigned
lzms_get_slot(u32 value, const u32 slot_base_tab[], unsigned num_slots);

/* Return the offset slot for the specified offset  */
static inline unsigned
lzms_get_offset_slot(u32 offset)
{
	return lzms_get_slot(offset, lzms_offset_slot_base, LZMS_MAX_NUM_OFFSET_SYMS);
}

/* Return the length slot for the specified length  */
static inline unsigned
lzms_get_length_slot(u32 length)
{
	return lzms_get_slot(length, lzms_length_slot_base, LZMS_NUM_LENGTH_SYMS);
}

extern unsigned
lzms_get_num_offset_slots(size_t uncompressed_size);


/* Probability entry for use by the range coder when in a specific state  */
struct lzms_probability_entry {

	/* The number of zeroes in the most recent LZMS_PROBABILITY_DENOMINATOR
	 * bits that have been decoded or encoded using this probability entry.
	 * The probability of the next bit being 0 is this value over
	 * LZMS_PROBABILITY_DENOMINATOR, except for the cases where this would
	 * imply 0% or 100% probability.  */
	u32 num_recent_zero_bits;

	/* The most recent LZMS_PROBABILITY_DENOMINATOR bits that have been
	 * coded using this probability entry.  The bits are ordered such that
	 * low order is newest and high order is oldest.  */
	u64 recent_bits;
};

struct lzms_probabilites {
	struct lzms_probability_entry main[LZMS_NUM_MAIN_PROBS];
	struct lzms_probability_entry match[LZMS_NUM_MATCH_PROBS];
	struct lzms_probability_entry lz[LZMS_NUM_LZ_PROBS];
	struct lzms_probability_entry delta[LZMS_NUM_DELTA_PROBS];
	struct lzms_probability_entry lz_rep[LZMS_NUM_LZ_REP_DECISIONS]
					    [LZMS_NUM_LZ_REP_PROBS];
	struct lzms_probability_entry delta_rep[LZMS_NUM_DELTA_REP_DECISIONS]
					       [LZMS_NUM_DELTA_REP_PROBS];
};

extern void
lzms_init_probabilities(struct lzms_probabilites *probs);

/* Given a decoded or encoded bit, update the probability entry.  */
static inline void
lzms_update_probability_entry(struct lzms_probability_entry *entry, int bit)
{
	STATIC_ASSERT(LZMS_PROBABILITY_DENOMINATOR == sizeof(entry->recent_bits) * 8);

#ifdef __x86_64__
	if (__builtin_constant_p(bit)) {
		/* Optimized implementation for x86_64 using carry flag  */
		if (bit) {
		       __asm__("shlq %[recent_bits]                          \n"
			       "adcl $0xffffffff, %[num_recent_zero_bits]    \n"
			       "orq $0x1, %[recent_bits]                     \n"
			       : [recent_bits] "+r" (entry->recent_bits),
				 [num_recent_zero_bits] "+mr" (entry->num_recent_zero_bits)
			       :
			       : "cc");
		} else {
		       __asm__("shlq %[recent_bits]                          \n"
			       "adcl $0x0, %[num_recent_zero_bits]           \n"
			       : [recent_bits] "+m" (entry->recent_bits),
				 [num_recent_zero_bits] "+mr" (entry->num_recent_zero_bits)
			       :
			       : "cc");
		}
	} else
#endif
	{
		s32 delta_zero_bits = (s32)(entry->recent_bits >>
					    (LZMS_PROBABILITY_DENOMINATOR - 1)) - bit;

		entry->num_recent_zero_bits += delta_zero_bits;
		entry->recent_bits = (entry->recent_bits << 1) | bit;
	}
}

/* Given a probability entry, return the chance out of
 * LZMS_PROBABILITY_DENOMINATOR that the next decoded bit will be a 0.  */
static inline u32
lzms_get_probability(const struct lzms_probability_entry *prob_entry)
{
	u32 prob = prob_entry->num_recent_zero_bits;

	/* 0% and 100% probabilities aren't allowed.  */

	/*
	 *	if (prob == 0)
	 *		prob++;
	 */
	prob += (u32)(prob - 1) >> 31;

	/*
	 *	if (prob == LZMS_PROBABILITY_DENOMINATOR)
	 *		prob--;
	 */
	prob -= (prob >> LZMS_PROBABILITY_BITS);

	return prob;
}

#ifdef __AVX2__
#  define LZMS_FREQS_ALIGNMENT 32
#  define LZMS_FREQS_ALIGNED	_aligned_attribute(32)
#elif defined(__SSE2__)
#  define LZMS_FREQS_ALIGNMENT 16
#  define LZMS_FREQS_ALIGNED	_aligned_attribute(16)
#else
#  define LZMS_FREQS_ALIGNMENT 4
#  define LZMS_FREQS_ALIGNED
#endif

extern void
lzms_init_symbol_frequencies(u32 freqs[], unsigned num_syms);

static inline void
lzms_dilute_symbol_frequencies(u32 freqs[], unsigned num_syms)
{
#ifdef __AVX2__
	const __m256i ones = _mm256_set1_epi32(1);
	__m256i *p = (__m256i *)freqs;
	unsigned count = num_syms / 16;
	while (count--) {
		p[0] = _mm256_add_epi32(_mm256_srli_epi32(p[0], 1), ones);
		p[1] = _mm256_add_epi32(_mm256_srli_epi32(p[1], 1), ones);
		p += 2;
	}
	for (unsigned sym = num_syms & ~15; sym < num_syms; sym++)
		freqs[sym] = (freqs[sym] >> 1) + 1;
#elif defined(__SSE2__)
	const __m128i ones = _mm_set1_epi32(1);
	__m128i *p = (__m128i *)freqs;
	unsigned count = num_syms / 16;
	while (count--) {
		p[0] = _mm_add_epi32(_mm_srli_epi32(p[0], 1), ones);
		p[1] = _mm_add_epi32(_mm_srli_epi32(p[1], 1), ones);
		p[2] = _mm_add_epi32(_mm_srli_epi32(p[2], 1), ones);
		p[3] = _mm_add_epi32(_mm_srli_epi32(p[3], 1), ones);
		p += 4;
	}
	for (unsigned sym = num_syms & ~15; sym < num_syms; sym++)
		freqs[sym] = (freqs[sym] >> 1) + 1;
#else
	for (unsigned sym = 0; sym < num_syms; sym++)
		freqs[sym] = (freqs[sym] >> 1) + 1;
#endif
}



/* Pre/post-processing  */
extern void
lzms_x86_filter(u8 data[], s32 size, s32 last_target_usages[], bool undo);

#endif /* _LZMS_COMMON_H */
