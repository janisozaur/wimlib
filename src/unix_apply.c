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

#if defined(HAVE_SYS_IOCTL_H) && \
	defined(HAVE_LINUX_MSDOS_FS_H) && \
	defined(HAVE_SYS_VFS_H)
#  include <linux/msdos_fs.h>
#  include <sys/ioctl.h>
#  include <sys/vfs.h>
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
#ifdef FAT_IOCTL_SET_ATTRIBUTES
	char *path, *p;
	struct statfs fsinfo;
	int res;

	path = STRDUP(target);
	if (!path)
		return WIMLIB_ERR_NOMEM;
	p = strchr(path, '\0');
	while (p > target && *(p - 1) == '/')
		p--;
	while (p > target && *(p - 1) != '/')
		p--;
	*p = '\0';
	res = statfs(path, &fsinfo);
	FREE(path);
	if (!res && fsinfo.f_type == MSDOS_SUPER_MAGIC) {
		/* FAT filesystem mounted on Linux  */
		supported_features->readonly_files = 1;
		supported_features->hidden_files = 1;
		supported_features->system_files = 1;
		supported_features->archive_files = 1;
		supported_features->timestamps = 1;
		return 0;
	}
#endif

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

/* Sets the timestamps on a file being extracted.
 *
 * Either @fd or @path must be specified (not -1 and not NULL, respectively).
 */
static int
unix_set_timestamps(int fd, const char *path, u64 atime, u64 mtime)
{
	{
		struct timespec times[2];

		times[0] = wim_timestamp_to_timespec(atime);
		times[1] = wim_timestamp_to_timespec(mtime);

		errno = ENOSYS;
#ifdef HAVE_FUTIMENS
		if (fd >= 0 && !futimens(fd, times))
			return 0;
#endif
#ifdef HAVE_UTIMENSAT
		if (fd < 0 && !utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW))
			return 0;
#endif
		if (errno != ENOSYS)
			return WIMLIB_ERR_SET_TIMESTAMPS;
	}
	{
		struct timeval times[2];

		times[0] = wim_timestamp_to_timeval(atime);
		times[1] = wim_timestamp_to_timeval(mtime);

		if (fd >= 0 && !futimes(fd, times))
			return 0;
		if (fd < 0 && !lutimes(path, times))
			return 0;
		return WIMLIB_ERR_SET_TIMESTAMPS;
	}
}

static int
unix_set_owner_and_group(int fd, const char *path, uid_t uid, gid_t gid)
{
	if (fd >= 0 && !fchown(fd, uid, gid))
		return 0;
	if (fd < 0 && !lchown(path, uid, gid))
		return 0;
	return WIMLIB_ERR_SET_SECURITY;
}

static int
unix_set_mode(int fd, const char *path, mode_t mode)
{
	if (fd >= 0 && !fchmod(fd, mode))
		return 0;
	if (fd < 0 && !chmod(path, mode))
		return 0;
	return WIMLIB_ERR_SET_SECURITY;
}

/*
 * Set metadata on an extracted file.
 *
 * @fd is an open file descriptor to the extracted file, or -1.  @path is the
 * path to the extracted file, or NULL.  If valid, this function uses @fd.
 * Otherwise, if valid, it uses @path.  Otherwise, it calculates the path to one
 * alias of the extracted file and uses it.
 */
static int
unix_set_metadata(int fd, const struct wim_dentry *dentry,
		  const char *path, struct unix_apply_ctx *ctx)
{
	const struct wim_inode *inode = dentry->d_inode;
	int ret;
	struct wimlib_unix_data unix_data;
	bool opened = false;

	if (fd < 0 && !path)
		path = unix_build_extraction_path(dentry, ctx);

#ifdef FAT_IOCTL_SET_ATTRIBUTES
	bool set_attributes =
		ctx->common.supported_features.readonly_files &&
		!(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES) &&
		!inode_is_symlink(inode);

	if (fd < 0 && set_attributes) {
		fd = open(path, O_RDONLY | O_NOFOLLOW);
		if (fd < 0) {
			ERROR_WITH_ERRNO("Can't open \"%s\"", path);
			ret = WIMLIB_ERR_OPEN;
			goto out;
		}
		opened = true;
	}
#endif

	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA)
	    && inode_get_unix_data(inode, &unix_data))
	{
		u32 uid = unix_data.uid;
		u32 gid = unix_data.gid;
		u32 mode = unix_data.mode;

		ret = unix_set_owner_and_group(fd, path, uid, gid);
		if (ret) {
			if (!path)
				path = unix_build_extraction_path(dentry, ctx);
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("Can't set uid=%"PRIu32" and "
						 "gid=%"PRIu32" on \"%s\"",
						 uid, gid, path);
				goto out;
			} else {
				WARNING_WITH_ERRNO("Can't set uid=%"PRIu32" and "
						   "gid=%"PRIu32" on \"%s\"",
						   uid, gid, path);
			}
		}

		ret = 0;
		if (!inode_is_symlink(inode))
			ret = unix_set_mode(fd, path, mode);
		if (ret) {
			if (!path)
				path = unix_build_extraction_path(dentry, ctx);
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("Can't set mode=0%"PRIo32" "
						 "on \"%s\"", mode, path);
				goto out;
			} else {
				WARNING_WITH_ERRNO("Can't set mode=0%"PRIo32" "
						   "on \"%s\"", mode, path);
			}
		}
	}

	ret = unix_set_timestamps(fd, path,
				  inode->i_last_access_time,
				  inode->i_last_write_time);
	if (ret) {
		if (!path)
			path = unix_build_extraction_path(dentry, ctx);
		if (ctx->common.extract_flags &
		    WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS)
		{
			ERROR_WITH_ERRNO("Can't set timestamps on \"%s\"", path);
			goto out;
		} else {
			WARNING_WITH_ERRNO("Can't set timestamps on \"%s\"", path);
		}
	}

#ifdef FAT_IOCTL_SET_ATTRIBUTES
	if (set_attributes &&
	    ioctl(fd, FAT_IOCTL_SET_ATTRIBUTES, &inode->i_attributes) &&
	    errno != ENOTTY)
	{
		if (!path)
			path = unix_build_extraction_path(dentry, ctx);
		WARNING_WITH_ERRNO("Can't set attributes on \"%s\"", path);
	}
#endif

	ret = 0;
out:
	if (opened)
		close(fd);
	return ret;
}

/* Extract all needed aliases of the @inode, where one alias, corresponding to
 * @first_dentry, has already been extracted to @first_path.  */
static int
unix_create_hardlinks(const struct wim_inode *inode,
		      const struct wim_dentry *first_dentry,
		      const char *first_path, struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	const char *newpath;

	if (!ctx->common.supported_features.hard_links)
		return 0;

	inode_for_each_extraction_alias(dentry, inode) {
		if (dentry == first_dentry)
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

/* If @dentry represents a directory, create it.  */
static int
unix_create_if_directory(const struct wim_dentry *dentry,
			 struct unix_apply_ctx *ctx)
{
	const char *path;
	struct stat stbuf;

	if (!should_extract_as_directory(dentry->d_inode))
		return 0;

	path = unix_build_extraction_path(dentry, ctx);
	if (mkdir(path, 0755) &&
	    /* It's okay if the path already exists, as long as it's a
	     * directory.  */
	    !(errno == EEXIST && !lstat(path, &stbuf) && S_ISDIR(stbuf.st_mode)))
	{
		ERROR_WITH_ERRNO("Can't create directory \"%s\"", path);
		return WIMLIB_ERR_MKDIR;
	}

	return report_file_created(&ctx->common);
}

/* If @dentry represents an empty regular file or a special file, create it, set
 * its metadata, and create any needed hard links.  */
static int
unix_extract_if_empty_file(const struct wim_dentry *dentry,
			   struct unix_apply_ctx *ctx)
{
	const struct wim_inode *inode;
	struct wimlib_unix_data unix_data;
	const char *path;
	int ret;

	inode = dentry->d_inode;

	/* Extract all aliases only when the "first" comes up.  */
	if (ctx->common.supported_features.hard_links &&
	    dentry != inode_first_extraction_dentry(inode))
		return 0;

	/* Is this a directory, a symbolic link, or any type of nonempty file?
	 */
	if (should_extract_as_directory(inode) || inode_is_symlink(inode) ||
	    inode_get_blob_for_unnamed_data_stream_resolved(inode))
		return 0;

	/* Recognize special files in UNIX_DATA mode  */
	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) &&
	    inode_get_unix_data(inode, &unix_data) &&
	    !S_ISREG(unix_data.mode))
	{
		path = unix_build_extraction_path(dentry, ctx);
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
		/* On special files, we can set timestamps immediately because
		 * we don't need to write any data to them.  */
		ret = unix_set_metadata(-1, dentry, path, ctx);
	} else {
		int fd;

		path = unix_build_extraction_path(dentry, ctx);
	retry_create:
		fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
		if (fd < 0) {
			if (errno == EEXIST && !unlink(path))
				goto retry_create;
			ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
			return WIMLIB_ERR_OPEN;
		}
		/* On empty files, we can set timestamps immediately because we
		 * don't need to write any data to them.  */
		ret = unix_set_metadata(fd, dentry, path, ctx);
		if (close(fd) && !ret) {
			ERROR_WITH_ERRNO("Error closing \"%s\"", path);
			ret = WIMLIB_ERR_WRITE;
		}
	}
	if (ret)
		return ret;

	ret = unix_create_hardlinks(inode, dentry, path, ctx);
	if (ret)
		return ret;

	return report_file_created(&ctx->common);
}

static int
unix_create_dirs_and_empty_files(const struct list_head *dentry_list,
				 struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = unix_create_if_directory(dentry, ctx);
		if (ret)
			return ret;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = unix_extract_if_empty_file(dentry, ctx);
		if (ret)
			return ret;
	}
	return 0;
}

static void
unix_count_dentries(const struct unix_apply_ctx *ctx,
		    const struct list_head *dentry_list,
		    u64 *dir_count_ret, u64 *empty_file_count_ret)
{
	const struct wim_dentry *dentry;
	u64 dir_count = 0;
	u64 empty_file_count = 0;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {

		const struct wim_inode *inode = dentry->d_inode;

		if (should_extract_as_directory(inode))
			dir_count++;
		else if ((dentry == inode_first_extraction_dentry(inode) ||
			  !ctx->common.supported_features.hard_links) &&
			 !inode_is_symlink(inode) &&
			 !inode_get_blob_for_unnamed_data_stream_resolved(inode))
			empty_file_count++;
	}

	*dir_count_ret = dir_count;
	*empty_file_count_ret = empty_file_count;
}

static int
unix_create_symlink(const struct wim_dentry *dentry, const char *path,
		    size_t rpdatalen, struct unix_apply_ctx *ctx)
{
	char target[REPARSE_POINT_MAX_SIZE];
	struct blob_descriptor blob_override;
	int ret;

	blob_set_is_located_in_attached_buffer(&blob_override,
					       ctx->reparse_data, rpdatalen);

	ret = wim_inode_readlink(dentry->d_inode, target, sizeof(target) - 1,
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
}

static int
unix_begin_extract_blob_instance(const struct blob_descriptor *blob,
				 const struct wim_dentry *dentry,
				 const struct wim_inode_stream *strm,
				 struct unix_apply_ctx *ctx)
{
	const char *path;
	int fd;

	if (unlikely(strm->stream_type == STREAM_TYPE_REPARSE_POINT)) {
		/* On UNIX, symbolic links must be created with symlink(), which
		 * requires that the full link target be available.  */
		if (blob->size > REPARSE_DATA_MAX_SIZE) {
			ERROR_WITH_ERRNO("Reparse data of \"%s\" has size "
					 "%"PRIu64" bytes (exceeds %u bytes)",
					 unix_build_extraction_path(dentry, ctx),
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

	path = unix_build_extraction_path(dentry, ctx);
retry_create:
	fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
	if (fd < 0) {
		if (errno == EEXIST && !unlink(path))
			goto retry_create;
		ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&ctx->open_fds[ctx->num_open_fds++], fd);
	return unix_create_hardlinks(dentry->d_inode, dentry, path, ctx);
}

/* Called when starting to read a blob for extraction  */
static int
unix_begin_extract_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);

	for (u32 i = 0; i < blob->out_refcnt; i++) {
		const struct wim_inode *inode = targets[i].inode;
		const struct wim_inode_stream *strm = targets[i].stream;
		const struct wim_dentry *dentry;

		inode_for_each_extraction_alias(dentry, inode) {
			int ret = unix_begin_extract_blob_instance(blob, dentry,
								   strm, ctx);
			if (ret) {
				ctx->reparse_ptr = NULL;
				unix_cleanup_open_fds(ctx, 0);
				return ret;
			}
			if (ctx->common.supported_features.hard_links)
				break;
		}
	}
	return 0;
}

/* Called when the next chunk of a blob has been read for extraction  */
static int
unix_extract_chunk(const void *chunk, size_t size, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	int ret;

	for (unsigned i = 0; i < ctx->num_open_fds; i++) {
		ret = full_write(&ctx->open_fds[i], chunk, size);
		if (ret) {
			ERROR_WITH_ERRNO("Error writing data to filesystem");
			return ret;
		}
	}
	if (ctx->reparse_ptr)
		ctx->reparse_ptr = mempcpy(ctx->reparse_ptr, chunk, size);
	return 0;
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
	for (u32 i = 0; i < blob->out_refcnt; i++) {
		const struct wim_inode *inode = targets[i].inode;
		const struct wim_dentry *dentry;

		inode_for_each_extraction_alias(dentry, inode) {
			if (inode_is_symlink(inode)) {
				/* We finally have the symlink data, so we can create
				 * the symlink.  */
				const char *path;

				path = unix_build_extraction_path(dentry, ctx);
				ret = unix_create_symlink(dentry, path, blob->size, ctx);
				if (ret) {
					ERROR_WITH_ERRNO("Can't create symbolic link "
							 "\"%s\"", path);
					goto out;
				}
				ret = unix_set_metadata(-1, dentry, path, ctx);
				if (ret)
					goto out;
			} else {
				/* Set metadata on regular file just before closing it.
				 */
				struct filedes *fd = &ctx->open_fds[j];

				ret = unix_set_metadata(fd->fd, dentry, NULL, ctx);
				if (ret)
					goto out;

				if (filedes_close(fd)) {
					ERROR_WITH_ERRNO("Error closing \"%s\"",
							 unix_build_extraction_path(dentry, ctx));
					ret = WIMLIB_ERR_WRITE;
					goto out;
				}
				j++;
			}
			if (ctx->common.supported_features.hard_links)
				break;
		}
	}
	ret = 0;
out:
	unix_cleanup_open_fds(ctx, j);
	return ret;
}

static int
unix_set_dir_metadata(struct list_head *dentry_list, struct unix_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	list_for_each_entry_reverse(dentry, dentry_list, d_extraction_list_node) {
		if (should_extract_as_directory(dentry->d_inode)) {
			ret = unix_set_metadata(-1, dentry, NULL, ctx);
			if (ret)
				return ret;
			ret = report_file_metadata_applied(&ctx->common);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int
unix_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	int ret;
	struct unix_apply_ctx *ctx = (struct unix_apply_ctx *)_ctx;
	size_t path_max;
	u64 dir_count;
	u64 empty_file_count;

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

	/* Extract directories and empty regular files.  Directories are needed
	 * because we can't extract any other files until their directories
	 * exist.  Empty files are needed because they don't have
	 * representatives in the blob list.  */

	unix_count_dentries(ctx, dentry_list, &dir_count, &empty_file_count);

	ret = start_file_structure_phase(&ctx->common, dir_count + empty_file_count);
	if (ret)
		goto out;

	ret = unix_create_dirs_and_empty_files(dentry_list, ctx);
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

	/* Extract nonempty regular files and symbolic links.  */

	struct read_blob_callbacks cbs = {
		.begin_blob	= unix_begin_extract_blob,
		.consume_chunk	= unix_extract_chunk,
		.end_blob	= unix_end_extract_blob,
		.ctx		= ctx,
	};
	ret = extract_blob_list(&ctx->common, &cbs);
	if (ret)
		goto out;


	/* Set directory metadata.  We do this last so that we get the right
	 * directory timestamps.  */
	ret = start_file_metadata_phase(&ctx->common, dir_count);
	if (ret)
		goto out;

	ret = unix_set_dir_metadata(dentry_list, ctx);
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
