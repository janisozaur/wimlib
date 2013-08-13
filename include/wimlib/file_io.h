#ifndef _WIMLIB_FILE_IO_H
#define _WIMLIB_FILE_IO_H

#include <stddef.h>
#include <sys/types.h>

struct filedes {
	int fd;
	unsigned int is_pipe : 1;
	off_t offset;
};

extern int
full_read(struct filedes *fd, void *buf, size_t n);

extern int
full_pread(struct filedes *fd, void *buf, size_t nbyte, off_t offset);

extern int
full_write(struct filedes *fd, const void *buf, size_t n);

extern int
full_pwrite(struct filedes *fd, const void *buf, size_t count, off_t offset);

extern ssize_t
raw_pread(struct filedes *fd, void *buf, size_t nbyte, off_t offset);

extern ssize_t
raw_pwrite(struct filedes *fd, const void *buf, size_t count, off_t offset);

#ifdef __WIN32__
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#else
struct iovec;
#endif

extern int
full_writev(struct filedes *fd, struct iovec *iov, int iovcnt);

#ifndef __WIN32__
#  define O_BINARY 0
#endif

extern off_t
filedes_seek(struct filedes *fd, off_t offset);

extern bool
filedes_is_seekable(struct filedes *fd);

static inline void filedes_init(struct filedes *fd, int raw_fd)
{
	fd->fd = raw_fd;
	fd->offset = 0;
	fd->is_pipe = 0;
}

static inline void filedes_invalidate(struct filedes *fd)
{
	fd->fd = -1;
}

static inline void filedes_copy(struct filedes *dst, const struct filedes *src)
{
	*dst = *src;
}

#define filedes_close(f) close((f)->fd)

static inline bool
filedes_valid(const struct filedes *fd)
{
	return fd->fd != -1;
}

#endif /* _WIMLIB_FILE_IO_H */
