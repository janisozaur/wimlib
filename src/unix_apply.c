/*
 * unix_apply.c - Code to apply files from a WIM image on UNIX.
 */

/*
 * Copyright (C) 2012-2016 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "wimlib/apply.h"
#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/reparse.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"

/* We don't require O_NOFOLLOW, but the advantage of having it is that if we
 * need to extract a file to a location at which there exists a symbolic link,
 * open(..., O_NOFOLLOW | ...) recognizes the symbolic link rather than
 * following it and creating the file somewhere else.  (Equivalent to
 * FILE_OPEN_REPARSE_POINT on Windows.)  */
#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
#endif

static int
unix_get_supported_features(const char *target,
			    struct wim_features *supported_features)
{
	supported_features->sparse_files = 1;
	supported_features->hard_links = 1;
	supported_features->symlink_reparse_points = 1;
	supported_features->unix_data = 1;
	supported_features->timestamps = 1;
	supported_features->case_sensitive_filenames = 1;
	return 0;
}

#define NUM_PATHBUFS 2  /* We need 2 when creating hard links  */

struct unix_apply_ctx {
	/* Extract flags, the pointer to the WIMStruct, etc.  */
	struct apply_ctx common;

	/* Buffers for building extraction paths (allocated).  */
	char *pathbufs[NUM_PATHBUFS];

	/* Index of next pathbuf to use  */
	unsigned which_pathbuf;

	/* Currently open file descriptors for extraction  */
	struct filedes open_fds[MAX_OPEN_FILES];

	/* Number of currently open file descriptors in open_fds, starting from
	 * the beginning of the array.  */
	unsigned num_open_fds;

	/* For each currently open file, whether we're writing to it in "sparse"
	 * mode or not.  */
	bool is_sparse_file[MAX_OPEN_FILES];

	/* Whether is_sparse_file[] is true for any currently open file  */
	bool any_sparse_files;

	/* Buffer for reading reparse point data into memory  */
	u8 reparse_data[REPARSE_DATA_MAX_SIZE];

	/* Pointer to the next byte in @reparse_data to fill  */
	u8 *reparse_ptr;

	/* Absolute path to the target directory (allocated buffer).  Only set
	 * if needed for absolute symbolic link fixups.  */
	char *target_abspath;

	/* Number of characters in target_abspath.  */
	size_t target_abspath_nchars;

	/* Number of special files we couldn't create due to EPERM  */
	unsigned long num_special_files_ignored;
};

/* Returns the number of characters needed to represent the path to the
 * specified @dentry when extracted, not including the null terminator or the
 * path to the target directory itself.  */
static size_t
unix_dentry_path_length(const struct wim_dentry *dentry)
{
	size_t len = 0;
	const struct wim_dentry *d;

	d = dentry;
	do {
		len += d->d_extraction_name_nchars + 1;
		d = d->d_parent;
	} while (!dentry_is_root(d) && will_extract_dentry(d));

	return len;
}

/* Returns the maximum number of characters needed to represent the path to any
 * dentry in @dentry_list when extracted, including the null terminator and the
 * path to the target directory itself.  */
static size_t
unix_compute_path_max(const struct list_head *dentry_list,
		      const struct unix_apply_ctx *ctx)
{
	size_t max = 0;
	size_t len;
	const struct wim_dentry *dentry;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		len = unix_dentry_path_length(dentry);
		if (len > max)
			max = len;
	}

	/* Account for target and null terminator.  */
	return ctx->common.target_nchars + max + 1;
}

/* Builds and returns the filesystem path to which to extract @dentry.
 * This cycles through NUM_PATHBUFS different buffers.  */
static const char *
unix_build_extraction_path(const struct wim_dentry *dentry,
			   struct unix_apply_ctx *ctx)
{
	char *pathbuf;
	char *p;
	const struct wim_dentry *d;

	pathbuf = ctx->pathbufs[ctx->which_pathbuf];
	ctx->which_pathbuf = (ctx->which_pathbuf + 1) % NUM_PATHBUFS;

	p = &pathbuf[ctx->common.target_nchars +
		     unix_dentry_path_length(dentry)];
	*p = '\0';
	d = dentry;
	do {
		p -= d->d_extraction_name_nchars;
		if (d->d_extraction_name_nchars)
			memcpy(p, d->d_extraction_name,
			       d->d_extraction_name_nchars);
		*--p = '/';
		d = d->d_parent;
	} while (!dentry_is_root(d) && will_extract_dentry(d));

	return pathbuf;
}

/* This causes the next call to unix_build_extraction_path() to use the same
 * path buffer as the previous call.  */
static void
unix_reuse_pathbuf(struct unix_apply_ctx *ctx)
{
	ctx->which_pathbuf = (ctx->which_pathbuf - 1) % NUM_PATHBUFS;
}

/* Builds and returns the filesystem path to which to extract an unspecified
 * alias of the @inode.  This cycles through NUM_PATHBUFS different buffers.  */
static const char *
unix_build_inode_extraction_path(const struct wim_inode *inode,
				 struct unix_apply_ctx *ctx)
{
	return unix_build_extraction_path(inode_first_extraction_dentry(inode), ctx);
}

/* Should the specified file be extracted as a directory on UNIX?  We extract
 * the file as a directory if FILE_ATTRIBUTE_DIRECTORY is set and the file does
 * not have a symlink or junction reparse point.  It *may* have a different type
 * of reparse point.  */
static inline bool
should_extract_as_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		!inode_is_symlink(inode);
}

/* Sets the timestamps on a file being extracted. */
static int
unix_set_timestamps(const char *path, u64 atime, u64 mtime)
{
#ifdef HAVE_UTIMENSAT
	{
		struct timespec times[2];

		times[0] = wim_timestamp_to_timespec(atime);
		times[1] = wim_timestamp_to_timespec(mtime);

		if (utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) == 0)
			return 0;
		if (errno != ENOSYS)
			return -1;
	}
#endif
	{
		struct timeval times[2];

		times[0] = wim_timestamp_to_timeval(atime);
		times[1] = wim_timestamp_to_timeval(mtime);

		return lutimes(path, times);
	}
}

/* Set metadata on an extracted file. */
static int
unix_set_metadata(const struct wim_inode *inode, struct unix_apply_ctx *ctx)
{
	const char *path = unix_build_inode_extraction_path(inode, ctx);
	struct wimlib_unix_data unix_data;

	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA)
	    && inode_get_unix_data(inode, &unix_data))
	{
		u32 uid = unix_data.uid;
		u32 gid = unix_data.gid;
		u32 mode = unix_data.mode;

		if (lchown(path, uid, gid) != 0) {
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("Can't set uid=%"PRIu32" and "
						 "gid=%"PRIu32" on \"%s\"",
						 uid, gid, path);
				return WIMLIB_ERR_SET_SECURITY;
			}
			WARNING_WITH_ERRNO("Can't set uid=%"PRIu32" and "
					   "gid=%"PRIu32" on \"%s\"",
					   uid, gid, path);
		}

		if (!inode_is_symlink(inode) && chmod(path, mode) != 0) {
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("Can't set mode=0%"PRIo32" "
						 "on \"%s\"", mode, path);
				return WIMLIB_ERR_SET_SECURITY;
			}
			WARNING_WITH_ERRNO("Can't set mode=0%"PRIo32" "
					   "on \"%s\"", mode, path);
		}
	}

	if (unix_set_timestamps(path, inode->i_last_access_time,
				inode->i_last_write_time) != 0)
	{
		if (ctx->common.extract_flags &
		    WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS)
		{
			ERROR_WITH_ERRNO("Can't set timestamps on \"%s\"", path);
			return WIMLIB_ERR_SET_TIMESTAMPS;
		}
		WARNING_WITH_ERRNO("Can't set timestamps on \"%s\"", path);
	}
	return 0;
}

/*
 * Extract all needed aliases of the specified @inode, where the first alias has
 * already been extracted to @first_path.
 */
static int
unix_create_hardlinks(const struct wim_inode *inode,
		      const char *first_path, struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	const char *newpath;

	inode_for_each_extraction_alias(dentry, inode) {
		if (dentry == inode_first_extraction_dentry(inode))
			continue;
		newpath = unix_build_extraction_path(dentry, ctx);
	retry_link:
		if (link(first_path, newpath)) {
			if (errno == EEXIST && !unlink(newpath))
				goto retry_link;
			ERROR_WITH_ERRNO("Can't create hard link "
					 "\"%s\" => \"%s\"", newpath, first_path);
			return WIMLIB_ERR_LINK;
		}
		unix_reuse_pathbuf(ctx);
	}
	return 0;
}

static int
unix_create_directory(const struct wim_dentry *dentry,
		      struct unix_apply_ctx *ctx)
{
	const char *path = unix_build_extraction_path(dentry, ctx);
	struct stat stbuf;

	if (mkdir(path, 0755) &&
	    /* It's okay if the path already exists, as long as it's a
	     * directory.  */
	    !(errno == EEXIST && !lstat(path, &stbuf) && S_ISDIR(stbuf.st_mode)))
	{
		ERROR_WITH_ERRNO("Can't create directory \"%s\"", path);
		return WIMLIB_ERR_MKDIR;
	}

	return 0;
}

static int
unix_create_nondirectory(const struct wim_inode *inode,
			 struct unix_apply_ctx *ctx)
{
	const char *path = unix_build_inode_extraction_path(inode, ctx);
	struct wimlib_unix_data unix_data;

	/* Recognize special files in UNIX_DATA mode  */
	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) &&
	    inode_get_unix_data(inode, &unix_data) &&
	    !S_ISREG(unix_data.mode))
	{
	retry_mknod:
		if (mknod(path, unix_data.mode, unix_data.rdev)) {
			if (errno == EPERM) {
				WARNING_WITH_ERRNO("Can't create special "
						   "file \"%s\"", path);
				ctx->num_special_files_ignored++;
				return 0;
			}
			if (errno == EEXIST && !unlink(path))
				goto retry_mknod;
			ERROR_WITH_ERRNO("Can't create special file \"%s\"",
					 path);
			return WIMLIB_ERR_MKNOD;
		}
	} else {
		int fd;

	retry_create:
		fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
		if (fd < 0) {
			if (errno == EEXIST && !unlink(path))
				goto retry_create;
			ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
			return WIMLIB_ERR_OPEN;
		}
		if (close(fd)) {
			ERROR_WITH_ERRNO("Error closing \"%s\"", path);
			return WIMLIB_ERR_WRITE;
		}
	}

	return unix_create_hardlinks(inode, path, ctx);
}

/* Create all files (and directories) except for symlinks. */
static int
unix_create_file_structure(const struct list_head *dentry_list,
			   struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	const struct wim_inode *inode;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		if (!should_extract_as_directory(inode))
			continue;
		ret = unix_create_directory(dentry, ctx);
		if (!ret)
			ret = report_file_created(&ctx->common);
		if (ret)
			return ret;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		if (should_extract_as_directory(inode) ||
		    inode_is_symlink(inode) ||
		    dentry != inode_first_extraction_dentry(inode))
			continue;
		ret = unix_create_nondirectory(inode, ctx);
		if (!ret)
			ret = report_file_created(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

static void
unix_count_inodes(const struct list_head *dentry_list,
		  u64 *full_count, u64 *symlink_count)
{
	const struct wim_dentry *dentry;

	*full_count = 0;
	*symlink_count = 0;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		if (dentry != inode_first_extraction_dentry(dentry->d_inode))
			continue;
		++*full_count;
		if (inode_is_symlink(dentry->d_inode))
			++*symlink_count;
	}
}

static int
unix_create_symlink(const struct wim_inode *inode, const char *path,
		    size_t rpdatalen, struct unix_apply_ctx *ctx)
{
	char target[REPARSE_POINT_MAX_SIZE];
	struct blob_descriptor blob_override;
	int ret;

	blob_set_is_located_in_attached_buffer(&blob_override,
					       ctx->reparse_data, rpdatalen);

	ret = wim_inode_readlink(inode, target, sizeof(target) - 1,
				 &blob_override,
				 ctx->target_abspath,
				 ctx->target_abspath_nchars);
	if (unlikely(ret < 0)) {
		errno = -ret;
		return WIMLIB_ERR_READLINK;
	}
	target[ret] = '\0';

retry_symlink:
	if (symlink(target, path)) {
		if (errno == EEXIST && !unlink(path))
			goto retry_symlink;
		return WIMLIB_ERR_LINK;
	}
	return 0;
}

static void
unix_cleanup_open_fds(struct unix_apply_ctx *ctx, unsigned offset)
{
	for (unsigned i = offset; i < ctx->num_open_fds; i++)
		filedes_close(&ctx->open_fds[i]);
	ctx->num_open_fds = 0;
	ctx->any_sparse_files = false;
}

static int
unix_begin_extract_blob_instance(const struct blob_descriptor *blob,
				 const struct wim_inode *inode,
				 const struct wim_inode_stream *strm,
				 struct unix_apply_ctx *ctx)
{
	const char *path = unix_build_inode_extraction_path(inode, ctx);
	int fd;

	if (unlikely(strm->stream_type == STREAM_TYPE_REPARSE_POINT)) {
		/* On UNIX, symbolic links must be created with symlink(), which
		 * requires that the full link target be available.  */
		if (blob->size > REPARSE_DATA_MAX_SIZE) {
			ERROR_WITH_ERRNO("Reparse data of \"%s\" has size "
					 "%"PRIu64" bytes (exceeds %u bytes)",
					 path,
					 blob->size, REPARSE_DATA_MAX_SIZE);
			return WIMLIB_ERR_INVALID_REPARSE_DATA;
		}
		ctx->reparse_ptr = ctx->reparse_data;
		return 0;
	}

	wimlib_assert(stream_is_unnamed_data_stream(strm));

	/* Unnamed data stream of "regular" file  */

	/* This should be ensured by extract_blob_list()  */
	wimlib_assert(ctx->num_open_fds < MAX_OPEN_FILES);

	fd = open(path, O_WRONLY | O_NOFOLLOW);
	if (fd < 0) {
		ERROR_WITH_ERRNO("Can't open regular file \"%s\"", path);
		return WIMLIB_ERR_OPEN;
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE) {
		ctx->is_sparse_file[ctx->num_open_fds] = true;
		ctx->any_sparse_files = true;
	} else {
		ctx->is_sparse_file[ctx->num_open_fds] = false;
#ifdef HAVE_POSIX_FALLOCATE
		posix_fallocate(fd, 0, blob->size);
#endif
	}
	filedes_init(&ctx->open_fds[ctx->num_open_fds++], fd);
	return 0;
}

/* Called when starting to read a blob for extraction  */
static int
unix_begin_extract_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);

	for (u32 i = 0; i < blob->out_refcnt; i++) {
		int ret = unix_begin_extract_blob_instance(blob,
							   targets[i].inode,
							   targets[i].stream,
							   ctx);
		if (ret) {
			ctx->reparse_ptr = NULL;
			unix_cleanup_open_fds(ctx, 0);
			return ret;
		}
	}
	return 0;
}

/* Called when the next chunk of a blob has been read for extraction  */
static int
unix_extract_chunk(const struct blob_descriptor *blob, u64 offset,
		   const void *chunk, size_t size, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	const void * const end = chunk + size;
	const void *p;
	bool zeroes;
	size_t len;
	unsigned i;
	int ret;

	/*
	 * For sparse files, only write nonzero regions.  This lets the
	 * filesystem use holes to represent zero regions.
	 */
	for (p = chunk; p != end; p += len, offset += len) {
		zeroes = maybe_detect_sparse_region(p, end - p, &len,
						    ctx->any_sparse_files);
		for (i = 0; i < ctx->num_open_fds; i++) {
			if (!zeroes || !ctx->is_sparse_file[i]) {
				ret = full_pwrite(&ctx->open_fds[i],
						  p, len, offset);
				if (ret)
					goto err;
			}
		}
	}

	if (ctx->reparse_ptr)
		ctx->reparse_ptr = mempcpy(ctx->reparse_ptr, chunk, size);
	return 0;

err:
	ERROR_WITH_ERRNO("Error writing data to filesystem");
	return ret;
}

/* Called when a blob has been fully read for extraction  */
static int
unix_end_extract_blob(struct blob_descriptor *blob, int status, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	int ret;
	unsigned j;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);

	ctx->reparse_ptr = NULL;

	if (status) {
		unix_cleanup_open_fds(ctx, 0);
		return status;
	}

	j = 0;
	ret = 0;
	for (u32 i = 0; i < blob->out_refcnt; i++) {
		struct wim_inode *inode = targets[i].inode;

		if (inode_is_symlink(inode)) {
			/* We finally have the symlink data, so we can create
			 * the symlink.  */
			const char *path;

			path = unix_build_inode_extraction_path(inode, ctx);
			ret = unix_create_symlink(inode, path, blob->size, ctx);
			if (ret) {
				ERROR_WITH_ERRNO("Can't create symbolic link "
						 "\"%s\"", path);
				break;
			}
		} else {
			struct filedes *fd = &ctx->open_fds[j];

			/* If the file is sparse, extend it to its final size. */
			if (ctx->is_sparse_file[j] && ftruncate(fd->fd, blob->size)) {
				ERROR_WITH_ERRNO("Error extending \"%s\" to final size",
						 unix_build_inode_extraction_path(inode, ctx));
				ret = WIMLIB_ERR_WRITE;
				break;
			}

			if (filedes_close(fd)) {
				ERROR_WITH_ERRNO("Error closing \"%s\"",
						 unix_build_inode_extraction_path(inode, ctx));
				ret = WIMLIB_ERR_WRITE;
				break;
			}
			j++;
		}
	}
	unix_cleanup_open_fds(ctx, j);
	return ret;
}

/* Apply metadata to all extracted files (and directories). */
static int
unix_apply_metadata(struct list_head *dentry_list, struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	const struct wim_inode *inode;
	int ret;

	list_for_each_entry_reverse(dentry, dentry_list, d_extraction_list_node)
	{
		inode = dentry->d_inode;
		if (dentry != inode_first_extraction_dentry(inode))
			continue;
		ret = unix_set_metadata(inode, ctx);
		if (!ret)
			ret = report_file_metadata_applied(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

static int
unix_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	int ret;
	struct unix_apply_ctx *ctx = (struct unix_apply_ctx *)_ctx;
	size_t path_max;
	u64 full_count;
	u64 symlink_count;

	/* Compute the maximum path length that will be needed, then allocate
	 * some path buffers.  */
	path_max = unix_compute_path_max(dentry_list, ctx);

	for (unsigned i = 0; i < NUM_PATHBUFS; i++) {
		ctx->pathbufs[i] = MALLOC(path_max);
		if (!ctx->pathbufs[i]) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
		/* Pre-fill the target in each path buffer.  We'll just append
		 * the rest of the paths after this.  */
		memcpy(ctx->pathbufs[i],
		       ctx->common.target, ctx->common.target_nchars);
	}

	/*
	 * We do the extraction in three phases:
	 *
	 *	1. Create all directories and files except for symlinks
	 *	2. Extract streams
	 *	3. Apply metadata
	 *
	 * In phase (2), the streams which may be extracted include unnamed data
	 * streams (regular file contents), reparse streams (translated to
	 * symlink targets), and extended attribute (xattr) streams.  These may
	 * come up for extraction in any order.  Therefore, at least when xattr
	 * streams are present, all files must be created earlier, in phase (1).
	 *
	 * Symlinks are an exception: they cannot be created until the reparse
	 * stream comes up for extraction.  Currently we hack around this by
	 * caching the xattrs of symlinks in memory until they can be applied
	 * between phases (2) and (3).
	 *
	 * Note that phase (3) must happen after all data all xattr extraction
	 * because it might set the file mode's to readonly (which precludes
	 * setxattr), and it also will set timestamps including the last
	 * modification time (which precludes write).
	 */

	unix_count_inodes(dentry_list, &full_count, &symlink_count);

	ret = start_file_structure_phase(&ctx->common,
					 full_count - symlink_count);
	if (ret)
		goto out;

	ret = unix_create_file_structure(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_structure_phase(&ctx->common);
	if (ret)
		goto out;

	/* Get full path to target if needed for absolute symlink fixups.  */
	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) &&
	    ctx->common.required_features.symlink_reparse_points)
	{
		ctx->target_abspath = realpath(ctx->common.target, NULL);
		if (!ctx->target_abspath) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
		ctx->target_abspath_nchars = strlen(ctx->target_abspath);
	}

	struct read_blob_callbacks cbs = {
		.begin_blob	= unix_begin_extract_blob,
		.continue_blob	= unix_extract_chunk,
		.end_blob	= unix_end_extract_blob,
		.ctx		= ctx,
	};
	ret = extract_blob_list(&ctx->common, &cbs);
	if (ret)
		goto out;

	ret = start_file_metadata_phase(&ctx->common, full_count);
	if (ret)
		goto out;

	ret = unix_apply_metadata(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_metadata_phase(&ctx->common);
	if (ret)
		goto out;

	if (ctx->num_special_files_ignored) {
		WARNING("%lu special files were not extracted due to EPERM!",
			ctx->num_special_files_ignored);
	}
out:
	for (unsigned i = 0; i < NUM_PATHBUFS; i++)
		FREE(ctx->pathbufs[i]);
	FREE(ctx->target_abspath);
	return ret;
}

const struct apply_operations unix_apply_ops = {
	.name			= "UNIX",
	.get_supported_features = unix_get_supported_features,
	.extract                = unix_extract,
	.context_size           = sizeof(struct unix_apply_ctx),
};
