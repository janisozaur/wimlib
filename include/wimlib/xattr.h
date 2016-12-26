#ifndef _WIMLIB_XATTR_H
#define _WIMLIB_XATTR_H

#include "wimlib/endianness.h"
#include "wimlib/sha1.h"
#include "wimlib/tagged_items.h"
#include "wimlib/util.h"

#undef HAVE_XATTR_SUPPORT
#if defined(HAVE_SYS_XATTR_H) && defined(HAVE_LLISTXATTR) && \
	defined(HAVE_LGETXATTR) && defined(HAVE_FSETXATTR)
#  define HAVE_XATTR_SUPPORT 1
#endif

/*
 * On-disk format of an entry in an extended attribute stream (wimlib
 * extension).  An xattr stream consists of a series of variable-length xattr
 * entries, each of which begins with this entry header.
 *
 * Currently this is only used for Linux-style xattrs, but in the future we may
 * use this for Windows-style xattrs too.
 */
struct wimlib_xattr_entry {

	/* length of xattr name in bytes */
	le16 name_len;

	/* reserved, must be 0 */
	le16 reserved;

	/* length of xattr value in bytes, not counting padding */
	le32 value_len;

	/* followed by the name with no terminating null */
	char name[0];

	/*
	 * directly followed by the value, zero-padded to the next 4-byte
	 * boundary if not already aligned
	 */
	/* u8 value[0]; */
};

static inline size_t
xattr_entry_size(const struct wimlib_xattr_entry *entry)
{
	return ALIGN(sizeof(*entry) + le16_to_cpu(entry->name_len) +
		     le32_to_cpu(entry->value_len), 4);
}

static inline struct wimlib_xattr_entry *
xattr_entry_next(const struct wimlib_xattr_entry *entry)
{
	return (void *)entry + xattr_entry_size(entry);
}

/* Currently we use the Linux limits when validating xattr names and values */
#define XATTR_NAME_MAX 255
#define XATTR_SIZE_MAX 65536

static inline bool
valid_xattr_entry(const struct wimlib_xattr_entry *entry, size_t avail)
{
	if (avail < sizeof(*entry))
		return false;

	if (entry->name_len == 0 ||
	    le16_to_cpu(entry->name_len) > XATTR_NAME_MAX)
		return false;

	if (entry->reserved != 0)
		return false;

	if (le32_to_cpu(entry->value_len) > XATTR_SIZE_MAX)
		return false;

	return avail >= xattr_entry_size(entry);
}

static inline const u8 *
inode_get_linux_xattr_hash(const struct wim_inode *inode)
{
	return inode_get_tagged_item(inode, TAG_WIMLIB_LINUX_XATTR_HASH,
				     SHA1_HASH_SIZE, NULL);
}

static inline bool
inode_has_linux_xattr_hash(const struct wim_inode *inode)
{
	return inode_get_linux_xattr_hash(inode) != NULL;
}

static inline bool
inode_set_linux_xattr_hash(struct wim_inode *inode, const u8 *hash)
{
	return inode_set_tagged_data(inode, TAG_WIMLIB_LINUX_XATTR_HASH,
				     hash, SHA1_HASH_SIZE);
}

#endif /* _WIMLIB_XATTR_H  */
