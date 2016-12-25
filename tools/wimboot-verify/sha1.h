#include <inttypes.h>
#include <stddef.h>

typedef struct {
	uint64_t bytecount;
	uint32_t state[5];
	uint8_t buffer[64];
} SHA_CTX;

extern void
sha1_init(SHA_CTX *ctx);

extern void
sha1_update(SHA_CTX *ctx, const void *data, size_t len);

extern void
sha1_final(uint8_t hash[20], SHA_CTX *ctx);
