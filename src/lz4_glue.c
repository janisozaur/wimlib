#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/error.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/util.h"

#include "lz4.h"
#include "lz4hc.h"

static int
lz4_decompress(const void *in, size_t in_nbytes,
	       void *out, size_t out_nbytes, void *_d)
{
	int res = LZ4_decompress_safe(in, out, in_nbytes, out_nbytes);

	if (res != (int)out_nbytes)
		return -1;
	return 0;
}

struct lz4_compressor {
	int hc_level;
};

static u64
lz4_get_needed_memory(size_t max_bufsize, unsigned compression_level,
		      bool destructive)
{
	return sizeof(struct lz4_compressor);
}

static int
lz4_create_compressor(size_t max_bufsize, unsigned compression_level,
		      bool destructive, void **c_ret)
{
	struct lz4_compressor *c;

	c = MALLOC(sizeof(*c));
	if (!c)
		return WIMLIB_ERR_NOMEM;

	if (compression_level <= 50) {
		c->hc_level = 0;
	} else {
		c->hc_level = LZ4HC_CLEVEL_MIN + (compression_level - 50) / 3;
		c->hc_level = min(LZ4HC_CLEVEL_MAX, c->hc_level);
	}

	*c_ret = c;
	return 0;
}

static size_t
lz4_compress(const void *in, size_t in_nbytes,
	     void *out, size_t out_nbytes_avail, void *_c)
{
	struct lz4_compressor *c = _c;

	if (c->hc_level)
		return LZ4_compress_HC(in, out, in_nbytes, out_nbytes_avail,
				       c->hc_level);

	return LZ4_compress_default(in, out, in_nbytes, out_nbytes_avail);
}

static void
lz4_free_compressor(void *c)
{
	FREE(c);
}

const struct decompressor_ops lz4_decompressor_ops = {
	.decompress = lz4_decompress,
};

const struct compressor_ops lz4_compressor_ops = {
	.get_needed_memory	= lz4_get_needed_memory,
	.create_compressor	= lz4_create_compressor,
	.compress		= lz4_compress,
	.free_compressor	= lz4_free_compressor,
};
