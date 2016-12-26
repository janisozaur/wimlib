#ifndef _WIMLIB_TAGGED_ITEMS_H
#define _WIMLIB_TAGGED_ITEMS_H

#include "wimlib/types.h"

struct wim_inode;

/* Windows-style object ID */
#define TAG_OBJECT_ID			0x00000001

/* [wimlib extension] Standard UNIX metadata: uid, gid, mode, and rdev */
#define TAG_WIMLIB_UNIX_DATA		0x337DD873

extern bool
inode_set_tagged_data(struct wim_inode *inode, u32 tag,
		      const void *data, u32 len);

extern void *
inode_get_tagged_item(const struct wim_inode *inode, u32 desired_tag,
		      u32 min_data_len, u32 *actual_len_ret);

#endif /* _WIMLIB_TAGGED_ITEMS_H */
