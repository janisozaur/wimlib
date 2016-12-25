/*
 * sha1.c
 *
 * Implementation of the Secure Hash Algorithm version 1 (FIPS 180-1).
 *
 * Author:  Eric Biggers
 * Year:    2014
 *
 * The default SHA-1 transform is based on public domain code by Steve Reid.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#include "sha1.h"
#include <string.h>

typedef uint32_t be32;
typedef uint64_t be64;

#define be32_to_cpu(x) __builtin_bswap32(x)
#define cpu_to_be32(x) __builtin_bswap32(x)
#define cpu_to_be64(x) __builtin_bswap64(x)

/* If we use libcrypto (e.g. OpenSSL) then we get all the SHA-1 functions for
 * free.  Otherwise we need to implement them ourselves.  */

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0(i) (tmp[i] = be32_to_cpu(((const be32 *)block)[i]))

#define blk(i) (tmp[i & 15] = rol(tmp[(i + 13) & 15] ^ \
				  tmp[(i +  8) & 15] ^ \
				  tmp[(i +  2) & 15] ^ \
				  tmp[(i +  0) & 15], 1))

#define R0(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);

#define R1(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);

#define R2(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
	w = rol(w, 30);

#define R3(v, w, x, y, z, i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);

#define R4(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w = rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm.  */
static void
sha1_transform(uint32_t state[5], const uint8_t block[64])
{
	uint32_t a, b, c, d, e;
	uint32_t tmp[16];

	/* Copy ctx->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

static void
sha1_transform_blocks(uint32_t state[5], const void *data, size_t num_blocks)
{
	do {
		sha1_transform(state, data);
		data += 64;
	} while (--num_blocks);
}

/* Initializes the specified SHA-1 context.
 *
 * After sha1_init(), call sha1_update() zero or more times to provide the data
 * to be hashed.  Then call sha1_final() to get the final hash.  */
void
sha1_init(SHA_CTX *ctx)
{
	ctx->bytecount = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

/* Updates the SHA-1 context with @len bytes of data.  */
void
sha1_update(SHA_CTX *ctx, const void *data, size_t len)
{
	unsigned buffered = ctx->bytecount & 63;

	ctx->bytecount += len;

	if (buffered) {
		/* Previous block is unfinished.  */
		if (len < 64 - buffered) {
			memcpy(&ctx->buffer[buffered], data, len);
			/* Previous block still unfinished.  */
			return;
		} else {
			memcpy(&ctx->buffer[buffered], data, 64 - buffered);
			/* Finished the previous block.  */
			sha1_transform_blocks(ctx->state, ctx->buffer, 1);
			data += 64 - buffered;
			len -= 64 - buffered;
		}
	}

	/* Process blocks directly from the input data.  */
	if (len / 64) {
		sha1_transform_blocks(ctx->state, data, len / 64);
		data += len & ~63;
		len &= 63;
	}

	/* Copy any remaining bytes to the buffer.  */
	if (len)
		memcpy(ctx->buffer, data, len);
}

/* Pad the message and generate the final SHA-1 message digest.  */
void
sha1_final(uint8_t md[20], SHA_CTX *ctx)
{
	/* Logically, we must append 1 bit, then a variable number of 0 bits,
	 * then the message length in bits as a big-endian integer, so that the
	 * final length is a multiple of the block size.  */
	static const uint8_t padding[64] = {0x80, };
	be64 finalcount = cpu_to_be64(ctx->bytecount << 3);
	be32 *out = (be32 *)md;

	sha1_update(ctx, padding, 64 - ((ctx->bytecount + 8) & 63));
	sha1_update(ctx, &finalcount, 8);

	for (int i = 0; i < 5; i++)
		out[i] = cpu_to_be32(ctx->state[i]);
}
