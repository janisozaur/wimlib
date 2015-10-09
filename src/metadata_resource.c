/*
 * metadata_resource.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"

/* Fix the security ID for every inode to be either -1 or in bounds.  */
static void
fix_security_ids(struct wim_image_metadata *imd, const u32 num_entries)
{
	struct wim_inode *inode;
	unsigned long invalid_count = 0;

	image_for_each_inode(inode, imd) {
		if ((u32)inode->i_security_id >= num_entries) {
			if (inode->i_security_id >= 0)
				invalid_count++;
			inode->i_security_id = -1;
		}
	}
	if (invalid_count)
		WARNING("%lu inodes had invalid security IDs", invalid_count);
}

/*
 * Reads and parses a metadata resource for an image in the WIM file.
 *
 * @imd:
 *	Pointer to the image metadata structure for the image whose metadata
 *	resource we are reading.  Its `metadata_blob' member specifies the blob
 *	table entry for the metadata resource.  The rest of the image metadata
 *	entry will be filled in by this function.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	WIMLIB_ERR_DECOMPRESSION
 */
int
read_metadata_resource(struct wim_image_metadata *imd)
{
	const struct blob_descriptor *metadata_blob;
	void *buf;
	int ret;
	u8 hash[SHA1_HASH_SIZE];
	struct wim_security_data *sd;
	struct wim_dentry *root;

	metadata_blob = imd->metadata_blob;

	/* Read the metadata resource into memory.  (It may be compressed.)  */
	ret = read_blob_into_alloc_buf(metadata_blob, &buf);
	if (ret)
		return ret;

	/* Checksum the metadata resource.  */
	sha1_buffer(buf, metadata_blob->size, hash);
	if (!hashes_equal(metadata_blob->hash, hash)) {
		ERROR("Metadata resource is corrupted "
		      "(invalid SHA-1 message digest)!");
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		goto out_free_buf;
	}

	/* Parse the metadata resource.
	 *
	 * Notes: The metadata resource consists of the security data, followed
	 * by the directory entry for the root directory, followed by all the
	 * other directory entries in the filesystem.  The subdir offset field
	 * of each directory entry gives the start of its child entries from the
	 * beginning of the metadata resource.  An end-of-directory is signaled
	 * by a directory entry of length '0', really of length 8, because
	 * that's how long the 'length' field is.  */

	ret = read_wim_security_data(buf, metadata_blob->size, &sd);
	if (ret)
		goto out_free_buf;

	ret = read_dentry_tree(buf, metadata_blob->size, sd->total_length, &root);
	if (ret)
		goto out_free_security_data;

	/* We have everything we need from the buffer now.  */
	FREE(buf);
	buf = NULL;

	/* Calculate and validate inodes.  */

	ret = dentry_tree_fix_inodes(root, &imd->inode_list);
	if (ret)
		goto out_free_dentry_tree;

	fix_security_ids(imd, sd->num_entries);

	/* Success; fill in the image_metadata structure.  */
	imd->root_dentry = root;
	imd->security_data = sd;
	INIT_LIST_HEAD(&imd->unhashed_blobs);
	return 0;

out_free_dentry_tree:
	free_dentry_tree(root, NULL);
out_free_security_data:
	free_wim_security_data(sd);
out_free_buf:
	FREE(buf);
	return ret;
}

static void
recalculate_security_data_length(struct wim_security_data *sd)
{
	u32 total_length = sizeof(u64) * sd->num_entries + 2 * sizeof(u32);
	for (u32 i = 0; i < sd->num_entries; i++)
		total_length += sd->sizes[i];
	sd->total_length = ALIGN(total_length, 8);
}

int
prepare_to_write_metadata_resource(struct wim_image_metadata *imd)
{
	int ret;
	u64 subdir_offset;
	struct wim_dentry *root;
	struct wim_security_data *sd;

	blob_release_location(imd->metadata_blob);

	root = imd->root_dentry;
	sd = imd->security_data;

	if (!root) {
		/* Empty image; create a dummy root.  */
		ret = new_filler_directory(&root);
		if (ret)
			return ret;
		imd->root_dentry = root;
	}

	/* The offset of the first child of the root dentry is equal to the
	 * total length of the security data, plus the total length of the root
	 * dentry, plus 8 bytes for an end-of-directory entry following the root
	 * dentry (shouldn't really be needed, but just in case...)  */
	recalculate_security_data_length(sd);
	subdir_offset = sd->total_length + dentry_out_total_length(root) + 8;

	/* Calculate the subdirectory offsets for the entire dentry tree.  */
	calculate_subdir_offsets(root, &subdir_offset);

	/* Update the metadata blob so that we can generate the metadata on
	 * demand.  */
	imd->metadata_blob->size = subdir_offset;
	imd->metadata_blob->blob_location = BLOB_IS_GENERATED_METADATA;
	imd->metadata_blob->imd = imd;

	return 0;
}

int
read_metadata_prefix(const struct blob_descriptor *blob, u64 size,
		     const struct read_blob_callbacks *cbs)
{
	struct wim_image_metadata *imd = blob->imd;
	u8 *buf;
	u8 *p;
	int ret;

	buf = NULL;
	if (likely((size_t)blob->size == blob->size))
		buf = MALLOC(blob->size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", blob->size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Write the security data into the resource buffer.  */
	p = write_wim_security_data(imd->security_data, buf);

	/* Write the dentry tree into the resource buffer.  */
	p = write_dentry_tree(imd->root_dentry, p);

	/* We MUST have exactly filled the buffer; otherwise we calculated its
	 * size incorrectly or wrote the data incorrectly.  */
	wimlib_assert(p - buf == blob->size);

	ret = call_consume_chunk(buf, size, cbs);
	FREE(buf);
	return ret;
}
