/*
 * decompress_common.c
 *
 * Code for decompression shared among multiple compression formats.
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2012-2016 by Eric Biggers <ebiggers3@gmail.com>
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>

#ifdef __SSE2__
#  include <emmintrin.h>
#endif

#include "wimlib/decompress_common.h"

#define MAKE_ENTRY(sym, len) (((sym) << DECODE_TABLE_SYMBOL_SHIFT) | (len))

/*
 * make_huffman_decode_table() -
 *
 * Build a decoding table for a canonical prefix code, or "Huffman code".  This
 * takes as input the length of the codeword for each symbol in the code and
 * produces as output a table for fast symbol decoding with read_huffsym().
 *
 * Because the code is assumed to be "canonical", it can be reconstructed
 * directly from the codeword lengths.  A prefix code is canonical if and only
 * if a longer codeword never lexicographically precedes a shorter codeword, and
 * the lexicographic ordering of codewords of the same length is the same as the
 * lexicographic ordering of the corresponding symbols.  Consequently, we can
 * sort the symbols primarily by codeword length and secondarily by symbol
 * value, then reconstruct the code by generating codewords lexicographically in
 * that order.
 *
 * This function does not, however, generate the code explicitly.  Instead, it
 * directly builds a table for decoding symbols using the code.  The basic idea
 * is this: given the next 'max_codeword_len' bits in the input, we can look up
 * the decoded symbol by indexing a table containing 2**max_codeword_len
 * entries.  A codeword with length 'max_codeword_len' will have exactly one
 * entry in this table, whereas a codeword shorter than 'max_codeword_len' will
 * have multiple entries in this table.  Precisely, a codeword of length n will
 * be represented by 2**(max_codeword_len - n) entries in this table.  The
 * 0-based index of each such entry will contain the corresponding codeword as a
 * prefix when zero-padded on the left to 'max_codeword_len' binary digits.
 *
 * That's the basic idea, but we implement two optimizations:
 *
 * - Often the maximum codeword length is too long for it to be efficient to
 *   build the full decoding table whenever a new code is used.  Instead, we can
 *   build the table using only 2**table_bits entries, where 'table_bits <=
 *   max_codeword_len'.  Then, a lookup of 'table_bits' bits will produce either
 *   a codeword directly (for codewords not longer than 'table_bits') or the
 *   index of a subtable which must be indexed with additional bits of input to
 *   decode the full codeword (for codewords longer than 'table_bits').
 *
 * - When we decode a symbol, we still need to know its codeword length so that
 *   the bitstream can be advanced by the appropriate number of bits.  The
 *   obvious solution is to simply retain the 'lens' array and use the decoded
 *   symbol as an index into it.  However, this requires two separate array
 *   accesses in the fast path.  The optimization is to store the length
 *   directly in the decode table, along with the symbol.
 *
 * @decode_table:
 *	The array in which to build the decode table.  This must have been
 *	declared by the DECODE_TABLE() macro.  This may alias @lens, since all
 *	@lens are consumed before the decode table is written to.
 *
 * @num_syms:
 *	The number of symbols in the alphabet.
 *
 * @table_bits:
 *	The log base 2 of the number of entries in the root table.
 *
 * @lens:
 *	An array of length @num_syms, indexable by symbol, that gives the length
 *	of the codeword, in bits, for that symbol.  The length can be 0, which
 *	means that the symbol does not have a codeword assigned.  In addition,
 *	@lens may alias @decode_table, as noted above.
 *
 * @max_codeword_len:
 *	The maximum codeword length permitted for this code.  All entries in
 *	'lens' must be less than or equal to this value.
 *
 * Returns 0 on success, or -1 if the lengths do not form a valid prefix code.
 */
int
make_huffman_decode_table(u16 decode_table[], unsigned num_syms,
			  unsigned table_bits, const u8 lens[],
			  unsigned max_codeword_len)
{
	u16 offsets[max_codeword_len + 1];
	u16 len_counts[max_codeword_len + 1];
	u16 sorted_syms[num_syms];
	s32 remainder = 1;
	void *entry_ptr = decode_table;
	unsigned codeword_len = 1;
	unsigned sym_idx;
	unsigned codeword;
	unsigned subtable_pos;
	unsigned subtable_bits;
	unsigned subtable_prefix;

	/* Count how many codewords have each length, including 0.  */
	for (unsigned len = 0; len <= max_codeword_len; len++)
		len_counts[len] = 0;
	for (unsigned sym = 0; sym < num_syms; sym++)
		len_counts[lens[sym]]++;

	/* It is already guaranteed that all lengths are <= max_codeword_len,
	 * but it cannot be assumed they form a complete prefix code.  A
	 * codeword of length n should require a proportion of the codespace
	 * equaling (1/2)^n.  The code is complete if and only if, by this
	 * measure, the codespace is exactly filled by the lengths.  */
	for (unsigned len = 1; len <= max_codeword_len; len++) {
		remainder = (remainder << 1) - len_counts[len];
		/* Do the lengths overflow the codespace? */
		if (unlikely(remainder < 0))
			return -1;
	}

	if (remainder != 0) {
		/* The lengths do not fill the codespace; that is, they form an
		 * incomplete code.  This is permitted only if the code is empty
		 * (contains no symbols). */

		if (unlikely(remainder != (s32)1 << max_codeword_len))
			return -1;

		/* The code is empty.  When processing a well-formed stream, the
		 * decode table need not be initialized in this case.  However,
		 * we cannot assume the stream is well-formed, so we must
		 * initialize the decode table anyway.  Setting all entries to 0
		 * makes this table always produce symbol '0' without consuming
		 * any bits, which is good enough. */
		memset(decode_table, 0,
		       (1U << table_bits) * sizeof(decode_table[0]));
		return 0;
	}

	/* Sort the symbols primarily by increasing codeword length and
	 * secondarily by increasing symbol value. */

	/* Initialize 'offsets' so that 'offsets[len]' is the number of
	 * codewords shorter than 'len' bits, including length 0. */
	offsets[0] = 0;
	for (unsigned len = 0; len < max_codeword_len; len++)
		offsets[len + 1] = offsets[len] + len_counts[len];

	/* Use the 'offsets' array to sort the symbols. */
	for (unsigned sym = 0; sym < num_syms; sym++)
		sorted_syms[offsets[lens[sym]]++] = sym;

	/*
	 * Fill entries for codewords with length <= table_bits
	 * --- that is, those short enough for a direct mapping.
	 *
	 * The table will start with entries for the shortest codeword(s), which
	 * have the most entries.  From there, the number of entries per
	 * codeword will decrease.  As an optimization, we may begin filling
	 * entries with SSE2 vector accesses (8 entries/store), then change to
	 * 'machine_word_t' accesses (2 or 4 entries/store), then change to
	 * 16-bit accesses (1 entry/store).
	 */
	sym_idx = offsets[0];
#ifdef __SSE2__
	/* Fill entries one 128-bit vector (8 entries) at a time. */
	for (unsigned stores_per_loop = (1U << (table_bits - codeword_len)) /
				    (sizeof(__m128i) / sizeof(decode_table[0]));
	     stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1)
	{
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			/* Note: unlike in the "word" version below, the __m128i
			 * type already has __attribute__((may_alias)), so using
			 * it to access an array of u16 will not violate strict
			 * aliasing.  */
			__m128i v = _mm_set1_epi16(
				MAKE_ENTRY(sorted_syms[sym_idx], codeword_len));
			unsigned n = stores_per_loop;
			do {
				*(__m128i *)entry_ptr = v;
				entry_ptr += sizeof(v);
			} while (--n);
		}
	}
#endif /* __SSE2__ */

#ifdef __GNUC__
	/* Fill entries one word (2 or 4 entries) at a time. */
	for (unsigned stores_per_loop = (1U << (table_bits - codeword_len)) /
					(WORDBYTES / sizeof(decode_table[0]));
	     stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1)
	{
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {

			/* Accessing the array of u16 as u32 or u64 would
			 * violate strict aliasing and would require compiling
			 * the code with -fno-strict-aliasing to guarantee
			 * correctness.  To work around this problem, use the
			 * gcc 'may_alias' extension.  */
			typedef machine_word_t
				__attribute__((may_alias)) aliased_word_t;
			aliased_word_t v = repeat_u16(
				MAKE_ENTRY(sorted_syms[sym_idx], codeword_len));
			unsigned n = stores_per_loop;

			do {
				*(aliased_word_t *)entry_ptr = v;
				entry_ptr += sizeof(v);
			} while (--n);
		}
	}
#endif /* __GNUC__ */

	/* Fill entries one at a time. */
	for (unsigned stores_per_loop = (1U << (table_bits - codeword_len));
	     stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1)
	{
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			u16 v = MAKE_ENTRY(sorted_syms[sym_idx], codeword_len);
			unsigned n = stores_per_loop;
			do {
				*(u16 *)entry_ptr = v;
				entry_ptr += sizeof(v);
			} while (--n);
		}
	}

	/* If all symbols were processed, then no subtables are required. */
	if (sym_idx == num_syms)
		return 0;

	/* At least one subtable is required.  Process the remaining symbols. */
	codeword = ((u16 *)entry_ptr - decode_table) << 1;
	subtable_pos = 1U << table_bits;
	subtable_bits = table_bits;
	subtable_prefix = -1;
	do {
		while (len_counts[codeword_len] == 0) {
			codeword_len++;
			codeword <<= 1;
		}

		unsigned prefix = codeword >> (codeword_len - table_bits);

		/* Start a new subtable if the first 'table_bits' bits of the
		 * codeword don't match the prefix for the previous subtable, or
		 * if this will be the first subtable. */
		if (prefix != subtable_prefix) {

			subtable_prefix = prefix;

			/* Calculate the subtable length.  If the codeword
			 * length exceeds 'table_bits' by n, the subtable needs
			 * at least 2**n entries.  But it may need more; if
			 * there are fewer than 2**n codewords of length
			 * 'table_bits + n' remaining, then n will need to be
			 * incremented to bring in longer codewords until the
			 * subtable can be filled completely.  Note that it
			 * always will, eventually, be possible to fill the
			 * subtable, since it was previously verified that the
			 * code is complete. */
			subtable_bits = codeword_len - table_bits;
			remainder = (s32)1 << subtable_bits;
			for (;;) {
				remainder -= len_counts[table_bits +
							subtable_bits];
				if (remainder <= 0)
					break;
				subtable_bits++;
				remainder <<= 1;
			}

			/* Create the entry that points from the root table to
			 * the subtable.  This entry contains the index of the
			 * start of the subtable and the number of bits with
			 * which the subtable is indexed (the log base 2 of the
			 * number of entries it contains).  */
			decode_table[subtable_prefix] =
				MAKE_ENTRY(subtable_pos, subtable_bits);
		}

		u16 entry = MAKE_ENTRY(sorted_syms[sym_idx],
				       codeword_len - table_bits);
		unsigned n = 1U << (subtable_bits - (codeword_len -
						     table_bits));
		do {
			decode_table[subtable_pos++] = entry;
		} while (--n);

		len_counts[codeword_len]--;
		codeword++;
	} while (++sym_idx < num_syms);

	return 0;
}
