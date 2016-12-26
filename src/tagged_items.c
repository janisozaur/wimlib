/*
 * tagged_items.c
 *
 * Support for tagged metadata items that can be appended to WIM directory
 * entries.
 */

/*
 * Copyright (C) 2014-2016 Eric Biggers
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

#include "wimlib/endianness.h"
#include "wimlib/inode.h"
#include "wimlib/tagged_items.h"
#include "wimlib/unix_data.h"

/* Header that begins each tagged metadata item in the metadata resource  */
struct tagged_item_header {

	/* Unique identifier for this item.  */
	le32 tag;

	/* Size of the data of this tagged item, in bytes.  This excludes this
	 * header and should be a multiple of 8.  */
	le32 length;

	/* Variable length data  */
	u8 data[];
};

/*
 * Retrieves the first tagged item with the specified tag and minimum length
 * from the specified inode.  Returns a pointer to the tagged data, which can be
 * read and/or modified in place, or NULL if not found.
 */
void *
inode_get_tagged_item(const struct wim_inode *inode, u32 desired_tag,
		      u32 min_data_len, u32 *actual_len_ret)
{
	size_t minlen_with_hdr = sizeof(struct tagged_item_header) + min_data_len;
	size_t len_remaining;
	u8 *p;

	if (!inode->i_extra)
		return NULL;

	len_remaining = inode->i_extra->size;
	p = inode->i_extra->data;

	/* Iterate through the tagged items.  */
	while (len_remaining >= minlen_with_hdr) {
		struct tagged_item_header *hdr;
		u32 tag;
		u32 len;

		hdr = (struct tagged_item_header *)p;
		tag = le32_to_cpu(hdr->tag);
		len = ALIGN(le32_to_cpu(hdr->length), 8);

		/* Length overflow?  */
		if (unlikely(len > len_remaining - sizeof(struct tagged_item_header)))
			return NULL;

		/* Matches the item we wanted?  */
		if (tag == desired_tag && len >= min_data_len) {
			if (actual_len_ret)
				*actual_len_ret = len;
			return hdr->data;
		}

		len_remaining -= sizeof(struct tagged_item_header) + len;
		p += sizeof(struct tagged_item_header) + len;
	}
	return NULL;
}

/*
 * Add a tagged item to the specified inode and return a pointer to its zeroed
 * data, which the caller may further initialize in-place.  No check is made for
 * whether the inode already has item(s) with the specified tag.
 */
static void *
inode_add_tagged_item(struct wim_inode *inode, u32 tag, u32 len)
{
	size_t itemsize;
	size_t newsize;
	struct wim_inode_extra *extra;
	struct tagged_item_header *hdr;

	/* We prepend the item instead of appending it because it's easier.  */

	itemsize = sizeof(struct tagged_item_header) + ALIGN(len, 8);
	newsize = itemsize;
	if (inode->i_extra)
		newsize += inode->i_extra->size;

	extra = MALLOC(sizeof(struct wim_inode_extra) + newsize);
	if (!extra)
		return NULL;
	if (inode->i_extra) {
		memcpy(&extra->data[itemsize], inode->i_extra->data,
		       inode->i_extra->size);
		FREE(inode->i_extra);
	}
	extra->size = newsize;
	inode->i_extra = extra;

	hdr = (struct tagged_item_header *)extra->data;
	hdr->tag = cpu_to_le32(tag);
	hdr->length = cpu_to_le32(len);
	return memset(hdr->data, 0, ALIGN(len, 8));
}

/*
 * Assign a tagged item containing the specified data to the specified inode,
 * removing any existing items with the same tag.  Returns %true if successful,
 * %false if failed (out of memory).
 */
bool
inode_set_tagged_data(struct wim_inode *inode, u32 tag,
		      const void *data, u32 len)
{
	u8 *p;
	u32 old_len;

	/* Remove any existing items with this tag */
	while ((p = inode_get_tagged_item(inode, tag, 0, &old_len)) != NULL) {
		p -= sizeof(struct tagged_item_header);
		old_len += sizeof(struct tagged_item_header);
		memmove(p, p + old_len, (inode->i_extra->data +
					 inode->i_extra->size) - (p + old_len));
		inode->i_extra->size -= old_len;
	}

	/* Add the new item */
	p = inode_add_tagged_item(inode, tag, len);
	if (!p)
		return false;
	memcpy(p, data, len);
	return true;
}

struct wimlib_unix_data_disk {
	le32 uid;
	le32 gid;
	le32 mode;
	le32 rdev;
};

static inline struct wimlib_unix_data_disk *
inode_get_unix_data_disk(const struct wim_inode *inode)
{
	return inode_get_tagged_item(inode, TAG_WIMLIB_UNIX_DATA,
				     sizeof(struct wimlib_unix_data_disk),
				     NULL);
}

/* Return %true iff the specified inode has standard UNIX metadata. */
bool
inode_has_unix_data(const struct wim_inode *inode)
{
	return inode_get_unix_data_disk(inode) != NULL;
}

/*
 * Get an inode's standard UNIX metadata.
 *
 * If the inode has standard UNIX metadata, returns %true and fills @unix_data.
 * Otherwise returns %false.
 */
bool
inode_get_unix_data(const struct wim_inode *inode,
		    struct wimlib_unix_data *unix_data)
{
	const struct wimlib_unix_data_disk *p;

	p = inode_get_unix_data_disk(inode);
	if (!p)
		return false;

	unix_data->uid = le32_to_cpu(p->uid);
	unix_data->gid = le32_to_cpu(p->gid);
	unix_data->mode = le32_to_cpu(p->mode);
	unix_data->rdev = le32_to_cpu(p->rdev);
	return true;
}

/*
 * Set an inode's standard UNIX metadata.
 *
 * Callers must specify all members in @unix_data.  If the inode does not yet
 * have standard UNIX metadata, it is given these values.  Otherwise, only the
 * values that also have the corresponding flags in @which set are changed.
 *
 * Returns %true if successful, %false if failed (out of memory).
 */
bool
inode_set_unix_data(struct wim_inode *inode, struct wimlib_unix_data *unix_data,
		    int which)
{
	struct wimlib_unix_data_disk *p;

	p = inode_get_unix_data_disk(inode);
	if (!p) {
		p = inode_add_tagged_item(inode, TAG_WIMLIB_UNIX_DATA,
					  sizeof(struct wimlib_unix_data_disk));
		if (!p)
			return false;
		which = UNIX_DATA_ALL;
	}
	if (which & UNIX_DATA_UID)
		p->uid = cpu_to_le32(unix_data->uid);
	if (which & UNIX_DATA_GID)
		p->gid = cpu_to_le32(unix_data->gid);
	if (which & UNIX_DATA_MODE)
		p->mode = cpu_to_le32(unix_data->mode);
	if (which & UNIX_DATA_RDEV)
		p->rdev = cpu_to_le32(unix_data->rdev);
	return true;
}
