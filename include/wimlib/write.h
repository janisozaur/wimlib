#ifndef _WIMLIB_WRITE_H
#define _WIMLIB_WRITE_H

#include "wimlib/types.h"

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
extern int
lock_wim_for_append(WIMStruct *wim);
extern void
unlock_wim_for_append(WIMStruct *wim);
#else
static inline int
lock_wim_for_append(WIMStruct *wim)
{
	return 0;
}
static inline void
unlock_wim_for_append(WIMStruct *wim)
{
}
#endif

struct filedes;
struct wim_reshdr;

extern int
write_wim_resource_from_buffer(const void *buf,
			       size_t buf_size,
			       bool is_metadata,
			       struct filedes *out_fd,
			       int out_ctype,
			       u32 out_chunk_size,
			       struct wim_reshdr *out_reshdr,
			       u8 *hash_ret,
			       int write_resource_flags);

#endif /* _WIMLIB_WRITE_H */
