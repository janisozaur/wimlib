#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/error.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/util.h"

#include "libdeflate.h"

static int
deflate_create_decompressor(size_t max_block_size, void **d_ret)
{
	*d_ret = libdeflate_alloc_decompressor();
	if (!*d_ret)
		return WIMLIB_ERR_NOMEM;
	return 0;
}

static int
deflate_decompress(const void *in, size_t in_nbytes,
		   void *out, size_t out_nbytes, void *_d)
{
	return libdeflate_deflate_decompress(_d, in, in_nbytes, out,
					     out_nbytes, NULL);
}

static void
deflate_free_decompressor(void *_d)
{
	libdeflate_free_decompressor(_d);
}

const struct decompressor_ops deflate_decompressor_ops = {
	.create_decompressor	= deflate_create_decompressor,
	.decompress		= deflate_decompress,
	.free_decompressor	= deflate_free_decompressor,
};

static int
deflate_create_compressor(size_t max_bufsize, unsigned compression_level,
		       bool destructive, void **c_ret)
{
	compression_level = compression_level / 8;
	compression_level = max(compression_level, 1);
	compression_level = min(compression_level, 12);

	*c_ret = libdeflate_alloc_compressor(compression_level);
	if (!*c_ret)
		return WIMLIB_ERR_NOMEM;

	return 0;
}

static size_t
deflate_compress(const void *in, size_t in_nbytes,
		 void *out, size_t out_nbytes_avail, void *_c)
{
	return libdeflate_deflate_compress(_c, in, in_nbytes,
					   out, out_nbytes_avail);
}

static void
deflate_free_compressor(void *_c)
{
	libdeflate_free_compressor(_c);
}

const struct compressor_ops deflate_compressor_ops = {
	.create_compressor	= deflate_create_compressor,
	.compress		= deflate_compress,
	.free_compressor	= deflate_free_compressor,
};
