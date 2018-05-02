#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/error.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/util.h"

#include <zstd.h>

static int
zstd_create_decompressor(size_t max_block_size, void **d_ret)
{
	*d_ret = ZSTD_createDCtx();
	if (!*d_ret)
		return WIMLIB_ERR_NOMEM;
	return 0;
}

static int
zstd_decompress(const void *in, size_t in_nbytes,
		void *out, size_t out_nbytes, void *_d)
{
	size_t res = ZSTD_decompressDCtx(_d, out, out_nbytes, in, in_nbytes);
	if (res != out_nbytes)
		return -1;
	return 0;
}

static void
zstd_free_decompressor(void *_d)
{
	ZSTD_freeDCtx(_d);
}

const struct decompressor_ops zstd_decompressor_ops = {
	.create_decompressor	= zstd_create_decompressor,
	.decompress		= zstd_decompress,
	.free_decompressor	= zstd_free_decompressor,
};
