/*
 * Copyright (c) 2014 Eric Biggers.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <ntstatus.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#include "avl_tree.h"

/*****************************************************************************/

/* Size of WIM resource (stream) hash fields  */
#define RESOURCE_HASH_SIZE 20

/* Useful macros  */
#define ARRAY_LEN(A) (sizeof(A) / sizeof((A)[0]))
#define TO_PERCENT(n, d) ((d) == 0 ? 0 : (double)(n) * 100 / (double)(d))

/*****************************************************************************/

/* Definitions for WOF (Windows Overlay File System Filter)  */

#define WOF_CURRENT_VERSION	1
#define WOF_PROVIDER_WIM	1
#define WIM_PROVIDER_CURRENT_VERSION 1

/* Identifies a backing provider for a specific overlay service version.  */
struct wof_external_info {

	/* Version of the overlay service supported by the backing provider.
	 * Set to WOF_CURRENT_VERSION.  */
	uint32_t version;

	/* Identifier for the backing provider.  Example value:
	 * WOF_PROVIDER_WIM.  */
	uint32_t provider;
};

struct wim_provider_external_info {

	/* Set to WIM_PROVIDER_CURRENT_VERSION.  */
	uint32_t version;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	uint32_t flags;

	/* Integer ID that identifies the WIM.  Get this with the
	 * FSCTL_ADD_OVERLAY ioctl.  */
	uint64_t data_source_id;

	/* SHA1 message digest of the file's unnamed data stream.  */
	uint8_t resource_hash[RESOURCE_HASH_SIZE];
};

/*
 * --- FSCTL_GET_EXTERNAL_BACKING ---
 *
 * Get external backing information for the specified file.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   196
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer: None
 * Output buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_external_info' in the case of WIM).
 */
#define FSCTL_GET_EXTERNAL_BACKING 0x90310

/*
 * --- FSCTL_ENUM_OVERLAY ---
 *
 * Enumerates the volume's overlay sources from the specified provider.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   199
 * Method:     3 (METHOD_NEITHER)
 *
 * Input buffer:  'struct wof_external_info' to specify the provider for which
 * to enumerate the overlay sources.
 *
 * Output buffer:  Provider-specific data.  For the WIM provider, an array of
 * 'struct wim_provider_overlay_entry'.
 *
 * This ioctl must be performed on the volume handle, such as \\.\C:
 */
#define FSCTL_ENUM_OVERLAY 0x9031F

struct wim_provider_overlay_entry {
	/* Byte offset of the next entry from the beginning of this structure,
	 * or 0 if there are no more entries.  */
	uint32_t next_entry_offset;

	uint32_t padding;

	/* Identifier for the WIM file.  */
	uint64_t data_source_id;

	/* GUID of the WIM file.  */
	uint8_t guid[16];

	/* Byte offset of the WIM's file name from the beginning of this
	 * structure.  */
	uint32_t wim_file_name_offset;

	/* Type of WIM file: WIM_BOOT_OS_WIM or WIM_BOOT_NOT_OS_WIM.  */
	uint32_t wim_type;

	/* Index of the backing image in the WIM??? (This doesn't really make
	 * sense, since WIM files combine streams for all images into a single
	 * table.)  */
	uint32_t wim_index;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	uint32_t flags;

	/* Full path to the WIM in the NT device namespace, e.g.
	 * "\Device\HardDiskVolume2\test.wim".  Seems to be null-terminated,
	 * although you probably shouldn't assume so.  */
	wchar_t wim_file_name[];
};

#ifndef STATUS_OBJECT_NOT_EXTERNALLY_BACKED
#  define STATUS_OBJECT_NOT_EXTERNALLY_BACKED 0xC000046D
#endif

/*****************************************************************************/

/* Global counters, updated during the directory tree scan  */
static struct {
	uint64_t unnamed_data_stream_nominal_size;
	uint64_t unnamed_data_stream_allocated_size;
	uint64_t named_data_stream_nominal_size;
	uint64_t named_data_stream_allocated_size;

	uint64_t named_data_streams;
	uint64_t reparse_points;
	uint64_t directories;
	uint64_t nondirectories;

	uint64_t externally_backed_files;
	uint64_t externally_backed_nominal_size;
	uint64_t externally_backed_allocated_size;
	uint64_t externally_backed_compressed_size;

	uint64_t sharing_violations;
	uint64_t sharing_violations_total_size;
} counters;

/*****************************************************************************/

/* Handle to ntdll.dll  */
static HMODULE hNtdll;

/* Functions loaded from ntdll.dll  */

static DWORD (WINAPI *func_RtlNtStatusToDosError)(NTSTATUS status);

static NTSTATUS (WINAPI *func_NtOpenFile) (PHANDLE FileHandle,
					   ACCESS_MASK DesiredAccess,
					   POBJECT_ATTRIBUTES ObjectAttributes,
					   PIO_STATUS_BLOCK IoStatusBlock,
					   ULONG ShareAccess,
					   ULONG OpenOptions);

static NTSTATUS (WINAPI *func_NtQueryInformationFile)(HANDLE FileHandle,
						      PIO_STATUS_BLOCK IoStatusBlock,
						      PVOID FileInformation,
						      ULONG Length,
						      FILE_INFORMATION_CLASS FileInformationClass);

static NTSTATUS (WINAPI *func_NtQueryObject) (HANDLE Handle,
					      OBJECT_INFORMATION_CLASS ObjectInformationClass,
					      PVOID ObjectInformation,
					      ULONG ObjectInformationLength,
					      PULONG ReturnLength);

static NTSTATUS (WINAPI *func_NtFsControlFile) (HANDLE FileHandle,
						HANDLE Event,
						PIO_APC_ROUTINE ApcRoutine,
						PVOID ApcContext,
						PIO_STATUS_BLOCK IoStatusBlock,
						ULONG FsControlCode,
						PVOID InputBuffer,
						ULONG InputBufferLength,
						PVOID OutputBuffer,
						ULONG OutputBufferLength);

static NTSTATUS (WINAPI *func_NtQueryDirectoryFile) (HANDLE FileHandle,
						     HANDLE Event,
						     PIO_APC_ROUTINE ApcRoutine,
						     PVOID ApcContext,
						     PIO_STATUS_BLOCK IoStatusBlock,
						     PVOID FileInformation,
						     ULONG Length,
						     FILE_INFORMATION_CLASS FileInformationClass,
						     BOOLEAN ReturnSingleEntry,
						     PUNICODE_STRING FileName,
						     BOOLEAN RestartScan);

static NTSTATUS (WINAPI *func_NtClose) (HANDLE Handle);

/*****************************************************************************/

/* Retrieves a human-readable error string for the specified Win32 error code.  */
static wchar_t *
win32_error_string(DWORD err_code)
{
	static wchar_t buf[1024];
	size_t len;

	buf[0] = L'\0';
	len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err_code, 0,
			     buf, ARRAY_LEN(buf), NULL);
	if (len > 0 && buf[len - 1] == L'\n')
		buf[--len] = L'\0';
	if (len > 0 && buf[len - 1] == L'\r')
		buf[--len] = L'\0';
	if (len > 0 && buf[len - 1] == L'.')
		buf[--len] = L'\0';
	return buf;
}

/* Retrieves a human-readable error string for the specified NTSTATUS error
 * code.  */
static wchar_t *
nt_error_string(NTSTATUS status)
{
	return win32_error_string((*func_RtlNtStatusToDosError)(status));
}

/* Translate the specified unsigned number into string form, with commas.  */
static const char *
u64_to_pretty_string(uint64_t num)
{
	static char bufs[4][30];
	static int which_buf = 0;

	which_buf = (which_buf + 1) % ARRAY_LEN(bufs);

	char *p = &bufs[which_buf][ARRAY_LEN(bufs[0]) - 1];
	unsigned int comma_count = 3;

	if (num == 0) {
		*--p = '0';
		return p;
	}

	do {
		if (comma_count == 0) {
			*--p = ',';
			comma_count = 3;
		}
		--comma_count;
		*--p = '0' + (num % 10);
	} while ((num /= 10) != 0);

	return p;
}

/* Prints the specified error message and exits the program with failure status.
 */
static void
fatal(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fputs("ERROR: ", stderr);
	vfprintf(stderr, fmt, va);
	fputc('\n', stderr);
	va_end(va);

	exit(1);
}

/* Prints the specified warning message.  */
static void
warn(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fputs("WARNING: ", stderr);
	vfprintf(stderr, fmt, va);
	fputc('\n', stderr);
	va_end(va);
}

/* Like malloc(), but abort the program on failure.  */
static void *
xmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (!p)
		fatal("Out of memory");
	return p;
}

/* Like realloc(), but abort the program on failure.  */
static void *
xrealloc(void *ptr, size_t size)
{
	void *p;

	p = realloc(ptr, size);
	if (!p)
		fatal("Out of memory");
	return p;
}

/* @path is a NT namespace name beginning with \Device\
 * Try to replace the device with the corresponding DOS device,
 * e.g. \Device\HardDiskVolume1\Windows => C:\Windows
 * Note that there seems to be no easy way to do this.
 */
static wchar_t *
replace_nt_device(wchar_t *path)
{
	wchar_t drive[3];
	wchar_t nt_device[1000];
	wchar_t *tmp;
	size_t nt_device_nchars;
	DWORD ret;

	tmp = wcschr(path + 9, L'\\');
	if (tmp)
		nt_device_nchars = tmp - path;
	else
		nt_device_nchars = wcslen(path);

	if (!wcsncmp(path, L"\\Device\\Mup\\", 12)) {
		/* Network path, like \Device\Mup\192.168.0.1\somedir\somefile  */
		path[10] = L'\\';
		return path + 10;
	}

	drive[1] = L':';
	drive[2] = L'\0';

	/* Go through each possible drive letter and see if the reverse mapping
	 * matches... */
	for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
		ret = QueryDosDevice(drive, nt_device, ARRAY_LEN(nt_device));
		if (!ret)
			continue;
		if (!wcsncmp(nt_device, path, nt_device_nchars)) {
			path[--nt_device_nchars] = drive[1];
			path[--nt_device_nchars] = drive[0];
			return &path[nt_device_nchars];
		}
	}
	/* Nothing matched.  Just keep the NT namespace path.  */
	return path;
}

/* Given an open handle and a path relative to it (both optional, but at least
 * one must be specified), return a statically allocated human-readable form of
 * the full path.  */
static const wchar_t *
printable_path(HANDLE h, const wchar_t *path)
{
	static uint8_t bufs[2][sizeof(OBJECT_NAME_INFORMATION) + 32768 * sizeof(wchar_t)]
			   __attribute__((aligned(8)));
	static int buf_index = 0;

	uint8_t *buf;
	NTSTATUS status;
	ULONG return_length;
	size_t i;
	wchar_t *res;

	buf = bufs[buf_index];
	buf_index = (buf_index + 1) % ARRAY_LEN(bufs);

	if (h == NULL) {
		res = wcscpy((wchar_t *)buf, path);
		goto out_nt_to_dos;
	}

	status = (*func_NtQueryObject)(h, ObjectNameInformation,
				       buf, sizeof(bufs[0]), &return_length);
	if (!NT_SUCCESS(status)) {
		res = wcscpy((wchar_t *)buf, path);
		goto out_nt_to_dos;
	}

	{
		OBJECT_NAME_INFORMATION *info = (OBJECT_NAME_INFORMATION *)buf;

		/* Strip trailing slash and append file name  */
		if (path) {
			i = info->Name.Length / sizeof(wchar_t);
			if (i > 0 && info->Name.Buffer[i - 1] != L'\\')
				info->Name.Buffer[i++] = L'\\';
			wcscpy(&info->Name.Buffer[i], path);
		}

		res = info->Name.Buffer;
	}

out_nt_to_dos:
	if (!wcsncmp(res, L"\\Device\\", 8))
		res = replace_nt_device(res);
	else if (!wcsncmp(res, L"\\??\\", 4))
		res += 4;
	return res;
}

static const wchar_t *
prettify_path(const wchar_t *path)
{
	return printable_path(NULL, path);
}

static const wchar_t *
handle_to_path(HANDLE h)
{
	return printable_path(h, NULL);
}

/* Load ntdll.dll and some native functions from it.  */
static void
init_ntdll(void)
{
	hNtdll = LoadLibrary(L"ntdll.dll");

	if (!hNtdll)
		fatal("Can't load ntdll.dll");

#define NTDLL_SYM(name) { (void **)&func_##name, #name }
	static const struct ntdll_sym {
		void **func_ptr;
		const char *name;
	} ntdll_syms[] = {
		NTDLL_SYM(RtlNtStatusToDosError),
		NTDLL_SYM(NtOpenFile),
		NTDLL_SYM(NtQueryInformationFile),
		NTDLL_SYM(NtQueryObject),
		NTDLL_SYM(NtFsControlFile),
		NTDLL_SYM(NtQueryDirectoryFile),
		NTDLL_SYM(NtClose),
		{NULL, NULL},
	};
#undef NTDLL_SYM

	for (const struct ntdll_sym *sym = ntdll_syms; sym->name; sym++) {
		void *addr = (void*)GetProcAddress(hNtdll, sym->name);
		if (!addr)
			fatal("Can't find %s in ntdll.dll", sym->name);
		*(sym->func_ptr) = addr;
	}
}

static int
cmp_u64(uint64_t n1, uint64_t n2)
{
	if (n1 < n2)
		return -1;
	else if (n1 > n2)
		return 1;
	else
		return 0;
}

/* Wrapper around an inode number.  */
struct visited_inode {
	/* Node in ino_set, indexed by ino.  */
	struct avl_tree_node index_node;
	uint64_t ino;
};

static struct visited_inode *cached_visited_inode = NULL;

/* Set of inode numbers that have been found so far  */
static struct avl_tree_node *ino_set = NULL;

static struct visited_inode *
alloc_visited_inode(void)
{
	struct visited_inode *p;

	if (cached_visited_inode) {
		p = cached_visited_inode;
		cached_visited_inode = NULL;
	} else {
		p = xmalloc(sizeof(*p));
	}
	return p;
}

static void
free_visited_inode(struct visited_inode *p)
{
	if (!cached_visited_inode)
		cached_visited_inode = p;
	else
		free(p);
}

static void
free_ino_set(void)
{
	struct visited_inode *p;

	avl_tree_for_each_in_postorder(p, ino_set,
				       struct visited_inode, index_node)
		free(p);

	free(cached_visited_inode);
}

static int
_avl_cmp_ino(const struct avl_tree_node *node1, const struct avl_tree_node *node2)
{
	return cmp_u64(avl_tree_entry(node1, struct visited_inode,
				      index_node)->ino,
		       avl_tree_entry(node2, struct visited_inode,
				      index_node)->ino);
}

/* Tests whether the specified inode number has been seen yet.
 * If no, insert it into the inode number set and return false.
 * If yes, return true.  */
static bool
inode_seen(uint64_t ino)
{
	struct visited_inode *p = alloc_visited_inode();

	p->ino = ino;

	if (!avl_tree_insert(&ino_set, &p->index_node, _avl_cmp_ino))
		return false;

	free_visited_inode(p);
	return true;
}

static bool wof_running;

struct perwim_counters {
	uint64_t nominal_size;
};

struct perwim_info {
	/* Node in perwim_info_set, indexed by wim_path.  */
	struct avl_tree_node index_node;

	/* Statistics about files that are externally backed by this WIM file.
	 */
	struct perwim_counters counters;

	/* Set of resources in this WIM that have seen to have been used in an
	 * external backing.  */
	struct avl_tree_node *visited_resources;

	/* Path to the WIM file.  */
	wchar_t wim_path[];
};

/* Set of 'perwim_info', one per each WIM registered as an external backing
 * source on the volume being scanned.  */
static struct avl_tree_node *perwim_info_set;

static int
_avl_cmp_wim_paths(const struct avl_tree_node *node1,
		   const struct avl_tree_node *node2)
{
	const wchar_t *path1, *path2;

	path1 = avl_tree_entry(node1, struct perwim_info, index_node)->wim_path;
	path2 = avl_tree_entry(node2, struct perwim_info, index_node)->wim_path;

	return wcscmp(path1, path2);
}

static int
_avl_cmp_wim_path(const void *_path1,
		  const struct avl_tree_node *node2)
{
	const wchar_t *path1, *path2;

	path1 = _path1;
	path2 = avl_tree_entry(node2, struct perwim_info, index_node)->wim_path;

	return wcscmp(path1, path2);
}

/* Given the path to a WIM file, return a 'struct perwim_info' representing it.
 * If the path is identical to that in other 'struct perwim_info', return the
 * duplicate instead of adding a new one.  */
static struct perwim_info *
get_perwim_info(const wchar_t *wim_path)
{
	struct avl_tree_node *node;
	struct perwim_info *p;

	node = avl_tree_lookup(perwim_info_set, wim_path, _avl_cmp_wim_path);
	if (node)
		return avl_tree_entry(node, struct perwim_info, index_node);

	p = xmalloc(sizeof(*p) + (wcslen(wim_path) + 1) * sizeof(wchar_t));

	memset(&p->counters, 0, sizeof(p->counters));
	wcscpy(p->wim_path, wim_path);
	p->visited_resources = NULL;
	avl_tree_insert(&perwim_info_set, &p->index_node, _avl_cmp_wim_paths);
	return p;
}

/* Mapping from WIM provider data source ID to 'struct perwim_info'.
 * A single WIM file may have multiple data source IDs and therefore multiple
 * entries in this map, but only one entry in 'struct perwim_info'.  */
static struct avl_tree_node *map_wim_id_to_perwim_info;

struct node_wim_id_to_perwim_info {
	/* Node in map_wim_id_to_perwim_info, indexed by wim_id.  */
	struct avl_tree_node index_node;

	/* The data source ID identifying the WIM.  */
	uint64_t wim_id;

	/* Actual per-WIM information, de-duplicated with other data source IDs.
	 */
	struct perwim_info *perwim_info;
};

static int
_avl_cmp_wim_ids(const struct avl_tree_node *node1, const struct avl_tree_node *node2)
{
	return cmp_u64(avl_tree_entry(node1, struct node_wim_id_to_perwim_info,
				      index_node)->wim_id,
		       avl_tree_entry(node2, struct node_wim_id_to_perwim_info,
				      index_node)->wim_id);
}

static int
_avl_cmp_wim_id(const void *_id1_ptr, const struct avl_tree_node *node2)
{
	return cmp_u64(*(const uint64_t *)_id1_ptr,
		       avl_tree_entry(node2, struct node_wim_id_to_perwim_info,
				      index_node)->wim_id);
}

/* Add a mapping from the specified data source ID to the specified WIM
 * information.  */
static void
add_wim_id_mapping(uint64_t wim_id, struct perwim_info *perwim_info)
{
	struct node_wim_id_to_perwim_info *p;

	p = xmalloc(sizeof(*p));

	p->wim_id = wim_id;
	p->perwim_info = perwim_info;
	if (avl_tree_insert(&map_wim_id_to_perwim_info, &p->index_node, _avl_cmp_wim_ids))
	{
		/* This only happens if FSCTL_ENUM_OVERLAY returns duplicate
		 * data source IDs (probably not possible).  */
		free(p);
	}
}

static void
do_load_wim_ids(uint8_t *buf, size_t bufsize)
{
	const struct wim_provider_overlay_entry *e;

	if (bufsize < sizeof(struct wim_provider_overlay_entry))
		return;

	e = (const struct wim_provider_overlay_entry *)buf;

	for (;;) {
		const wchar_t *wim_file_name;

		wim_file_name = (wchar_t *)((uint8_t *)e + e->wim_file_name_offset);

		add_wim_id_mapping(e->data_source_id, get_perwim_info(wim_file_name));

		if (e->next_entry_offset == 0)
			break;

		e = (const struct wim_provider_overlay_entry *)
			((const uint8_t *)e + e->next_entry_offset);
	}

}

/* Given a handle to any file on the volume being scanned, query the WOF driver
 * for the list af WIM files registered as backing sources on the volume, then
 * prepare data in memory for each data source ID and WIM file.  */
static void
load_wim_ids(HANDLE h)
{
	uint8_t *buf;
	size_t bufsize = 8192;
	struct wof_external_info in;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	in.version = WOF_CURRENT_VERSION;
	in.provider = WOF_PROVIDER_WIM;

	buf = xmalloc(bufsize);

retry:
	status = (*func_NtFsControlFile)(h, NULL, NULL, NULL, &iosb,
					 FSCTL_ENUM_OVERLAY,
					 &in, sizeof(in), buf, bufsize);
	if (status == STATUS_BUFFER_OVERFLOW) {
		bufsize *= 2;
		buf = xrealloc(buf, bufsize);
		goto retry;
	}

	if (NT_SUCCESS(status)) {
		do_load_wim_ids(buf, bufsize);
	} else {
		warn("\"%ls\": Failed to load backing WIM IDs (%ls)",
		     handle_to_path(h), nt_error_string(status));
	}

	free(buf);
}

/* Given the data source ID for a WIM file on the volume being scanned, look up
 * the per-WIM information for it.  Returns NULL if not found.  */
static struct perwim_info *
lookup_perwim_info(uint64_t wim_id)
{
	struct avl_tree_node *node;

	node = avl_tree_lookup(map_wim_id_to_perwim_info, &wim_id, _avl_cmp_wim_id);
	if (!node) {
		/* This should only be possible if a new data source was added
		 * after we did the FSCTL_ENUM_OVERLAY ioctl.  */
		return NULL;
	}

	return avl_tree_entry(node, struct node_wim_id_to_perwim_info,
			      index_node)->perwim_info;
}

/* Given the data source ID of a backing WIM file and the metadata for a file
 * being backed by it, accumulate some statistics.  */
static void
tally_perwim_info(uint64_t wim_id, const FILE_ALL_INFORMATION *file_info)
{
	struct perwim_info *p;

	p = lookup_perwim_info(wim_id);
	if (!p)
		return;

	p->counters.nominal_size += file_info->StandardInformation.EndOfFile.QuadPart;
}

/* Wrapper around a WIM resource (stream) hash.  */
struct visited_resource {
	/* Node in 'struct perwim_info.visited_resources', indexed by hash.  */
	struct avl_tree_node index_node;

	uint8_t hash[RESOURCE_HASH_SIZE];
};

static struct visited_resource *cached_visited_resource = NULL;

static struct visited_resource *
alloc_visited_resource(void)
{
	struct visited_resource *p;

	if (cached_visited_resource) {
		p = cached_visited_resource;
		cached_visited_resource = NULL;
	} else {
		p = xmalloc(sizeof(*p));
	}
	return p;
}

static void
free_visited_resource(struct visited_resource *p)
{
	if (!cached_visited_resource)
		cached_visited_resource = p;
	else
		free(p);
}

static int
_avl_cmp_resource_hashes(const struct avl_tree_node *node1,
			 const struct avl_tree_node *node2)
{
	return memcmp(avl_tree_entry(node1, struct visited_resource, index_node)->hash,
		      avl_tree_entry(node2, struct visited_resource, index_node)->hash,
		      RESOURCE_HASH_SIZE);
}

/* Given the data source ID of a backing WIM file and the hash (SHA1 message
 * digest, actually) of a resource that is backed inside it, return %true if
 * the same-hashed resource was already found to be used by another externally
 * backed file.  Otherwise, save the resource hash and return %false.  */
static bool
resource_seen(uint64_t wim_id, const uint8_t resource_hash[RESOURCE_HASH_SIZE])
{
	struct perwim_info *p;
	struct visited_resource *res;

	p = lookup_perwim_info(wim_id);
	if (!p)
		return false;

	res = alloc_visited_resource();

	memcpy(res->hash, resource_hash, RESOURCE_HASH_SIZE);

	if (!avl_tree_insert(&p->visited_resources, &res->index_node,
			     _avl_cmp_resource_hashes))
		return false;

	free_visited_resource(res);
	return true;
}

/* Free map_wim_id_to_perwim_info and perwim_info_set  */
static void
free_wim_info(void)
{
	struct node_wim_id_to_perwim_info *p1;
	struct perwim_info *p2;
	struct visited_resource *res;

	avl_tree_for_each_in_postorder(p1, map_wim_id_to_perwim_info,
				       struct node_wim_id_to_perwim_info, index_node)
	{
		free(p1);
	}

	avl_tree_for_each_in_postorder(p2, perwim_info_set,
				       struct perwim_info, index_node)
	{
		avl_tree_for_each_in_postorder(res, p2->visited_resources,
					       struct visited_resource, index_node)
		{
			free(res);
		}
		free(p2);
	}
}

/* Given an open handle to any file on the volume being scanned, detect if the
 * WOF driver is available.  If yes, set wof_running to true and load the list
 * of WIM files that have been registered as backing sources on the volume.
 * Otherwise, print a warning message and set wof_running to false.  */
static void
detect_wof(HANDLE h)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	status = (*func_NtFsControlFile)(h, NULL, NULL, NULL, &iosb,
					 FSCTL_GET_EXTERNAL_BACKING,
					 NULL, 0, NULL, 0);

	if (status == STATUS_OBJECT_NOT_EXTERNALLY_BACKED ||
	    status == STATUS_BUFFER_TOO_SMALL)
	{
		load_wim_ids(h);
		wof_running = true;
		return;
	}

	warn("\"%ls\": The Windows Overlay File System Filter is not running.\n"
	     "         It will be impossible to determine which files (if any) are\n"
	     "         externally backed (e.g. are WIMBoot pointer files)!\n",
	     handle_to_path(h));

	wof_running = false;
}

enum backing {
	/* It is unknown whether the file is externally backed or not.  */
	BACKING_UNKNOWN = 0x0,

	/* The file is not externally backed.  */
	BACKING_INTERNAL = 0x1,

	/* The file is externally backed.  */
	BACKING_EXTERNAL = 0x2,

	/* The file is externally backed, specifically in a WIM file.  */
	BACKING_EXTERNAL_WIM = 0x4 | BACKING_EXTERNAL,
};

/* Determines the externaly backing status of a file.
 *
 * @h
 *	Open handle to the file.
 * @wim_id_ret
 *	If return value is BACKING_EXTERNAL_WIM, this will be set to the data
 *	source ID of the backing WIM.
 * @resource_hash_ret
 *	If return value is BACKING_EXTERNAL_WIM, this will be filled in with the
 *	SHA1 message digest of the file's contents (unnamed data stream, which
 *	is being backed in the WIM).
 *
 * Returns one of the 'enum backing' values.
 */
static enum backing
get_external_backing(HANDLE h, uint64_t *wim_id_ret,
		     uint8_t resource_hash_ret[RESOURCE_HASH_SIZE])
{
	struct {
		struct wof_external_info wof_info;
		struct wim_provider_external_info wim_info;
	} out;
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	if (!wof_running)
		return BACKING_UNKNOWN;

	status = (*func_NtFsControlFile)(h, NULL, NULL, NULL, &iosb,
					 FSCTL_GET_EXTERNAL_BACKING,
					 NULL, 0, &out, sizeof(out));

	if (status == STATUS_OBJECT_NOT_EXTERNALLY_BACKED)
		return BACKING_INTERNAL;

	if (status == STATUS_BUFFER_TOO_SMALL ||
	    status == STATUS_BUFFER_OVERFLOW)
		return BACKING_EXTERNAL;

	if (!NT_SUCCESS(status)) {
		warn("\"%ls\": FSCTL_GET_EXTERNAL_BACKING failed (%ls)",
		     handle_to_path(h), nt_error_string(status));
		return BACKING_UNKNOWN;
	}

	if (iosb.Information < sizeof(struct wof_external_info)) {
		warn("\"%ls\": weird results from FSCTL_GET_EXTERNAL_BACKING",
		     handle_to_path(h));
		return BACKING_UNKNOWN;
	}

	if (out.wof_info.provider == WOF_PROVIDER_WIM) {
		*wim_id_ret = out.wim_info.data_source_id;
		memcpy(resource_hash_ret, out.wim_info.resource_hash, RESOURCE_HASH_SIZE);
		return BACKING_EXTERNAL_WIM;
	}

	return BACKING_EXTERNAL;
}

static void
analyze(HANDLE cur_dir, const wchar_t *path, size_t path_nchars,
	const FILE_ID_BOTH_DIR_INFORMATION *info);

/* Recursively analyze the children of the specified open directory.  */
static void
recurse_directory(HANDLE h)
{
	uint8_t *buf;
	const size_t bufsize = 8192;
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	buf = xmalloc(bufsize + sizeof(wchar_t));

	while (NT_SUCCESS(status = (*func_NtQueryDirectoryFile)(h, NULL, NULL, NULL,
								&iosb, buf, bufsize,
								FileIdBothDirectoryInformation,
								FALSE, NULL, FALSE)))
	{
		FILE_ID_BOTH_DIR_INFORMATION *info;

		info = (FILE_ID_BOTH_DIR_INFORMATION *)buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				wchar_t save = info->FileName[info->FileNameLength /
								sizeof(wchar_t)];

				info->FileName[info->FileNameLength /
							sizeof(wchar_t)] = L'\0';

				analyze(h, info->FileName,
					info->FileNameLength / sizeof(wchar_t),
					info);

				info->FileName[info->FileNameLength /
							sizeof(wchar_t)] = save;
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (FILE_ID_BOTH_DIR_INFORMATION *)
					((uint8_t *)info + info->NextEntryOffset);
		}
	}

	free(buf);
	if (status != STATUS_NO_MORE_FILES) {
		if (status == STATUS_INVALID_INFO_CLASS) {
			fatal("NtQueryDirectoryFile() does not support "
			      "FileIdBothDirectoryInformation!");
		} else {
			warn("\"%ls\": Can't read directory (%ls)",
			     handle_to_path(h), nt_error_string(status));
		}
	}
}

/* Accumulate statistics for the named data streams of the specified open file.
 */
static void
tally_named_data_streams(HANDLE h)
{
	uint8_t _buf[8192] __attribute__((aligned(8)));
	uint8_t *buf;
	size_t bufsize;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	const FILE_STREAM_INFORMATION *info;

	buf = _buf;
	bufsize = sizeof(_buf);

retry:
	status = (*func_NtQueryInformationFile)(h, &iosb, buf, bufsize,
						FileStreamInformation);
	if (!NT_SUCCESS(status)) switch (status) {
	case STATUS_BUFFER_OVERFLOW:
		bufsize *= 2;
		if (buf == _buf)
			buf = xmalloc(bufsize);
		else
			buf = xrealloc(buf, bufsize);

		goto retry;

	case STATUS_NOT_IMPLEMENTED:
	case STATUS_NOT_SUPPORTED:
	case STATUS_INVALID_INFO_CLASS:
	case STATUS_INVALID_PARAMETER:
		goto out_free_buf;

	default:
		warn("\"%ls\": can't query stream information (%ls)",
		     handle_to_path(h), nt_error_string(status));
		goto out_free_buf;
	}

	if (iosb.Information == 0)
		goto out_free_buf;

	info = (const FILE_STREAM_INFORMATION *)buf;
	for (;;) {
		const wchar_t *stream_type;
		if (info->StreamName[0] == L':' &&
		    info->StreamName[1] != L':' &&
		    (stream_type = wcschr(&info->StreamName[1], L':')) &&
		    !wcscmp(stream_type + 1, L"$DATA"))
		{
			counters.named_data_streams++;
			counters.named_data_stream_nominal_size +=
				info->StreamSize.QuadPart;
			counters.named_data_stream_allocated_size +=
				info->StreamAllocationSize.QuadPart;
		}
		if (info->NextEntryOffset == 0)
			break;
		info = (const FILE_STREAM_INFORMATION *)
				((const uint8_t *)info + info->NextEntryOffset);
	}
out_free_buf:
	if (buf != _buf)
		free(buf);
}

static NTSTATUS
open_file(HANDLE cur_dir, const wchar_t *path, size_t path_nchars, HANDLE *h_ret)
{
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK iosb;

	name.Length = path_nchars * sizeof(wchar_t);
	name.MaximumLength = name.Length + sizeof(wchar_t);
	name.Buffer = (wchar_t *)path;

	attr.Length = sizeof(attr);
	attr.RootDirectory = cur_dir;
	attr.ObjectName = &name;
	attr.Attributes = 0;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;

	return (*func_NtOpenFile)(h_ret,
				  FILE_READ_ATTRIBUTES |
					  FILE_LIST_DIRECTORY |
					  SYNCHRONIZE,
				  &attr,
				  &iosb,
				  FILE_SHARE_READ |
					  FILE_SHARE_WRITE |
					  FILE_SHARE_DELETE,
				  FILE_OPEN_REPARSE_POINT |
					  FILE_OPEN_FOR_BACKUP_INTENT |
					  FILE_SYNCHRONOUS_IO_NONALERT);
}

/* Query "all" metadata about the specified file.  */
static NTSTATUS
query_all_file_info(HANDLE h, FILE_ALL_INFORMATION *file_info)
{
	IO_STATUS_BLOCK iosb;
	return (*func_NtQueryInformationFile)(h,
					      &iosb,
					      file_info,
					      sizeof(FILE_ALL_INFORMATION),
					      FileAllInformation);
}

/* Query the compressed size of the file.
 * For files backed in a WIM, this returns the compressed size of the unnamed
 * data stream in the WIM file.  */
static NTSTATUS
query_compressed_size(HANDLE h, uint64_t *csize_ret)
{
	struct {
		LARGE_INTEGER CompressedFileSize;
		USHORT CompressionFormat;
		UCHAR CompressionUnitShift;
		UCHAR ChunkShift;
		UCHAR ClusterShift;
		UCHAR Reserved[3];
	} info;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	status = (*func_NtQueryInformationFile)(h,
						&iosb,
						&info,
						sizeof(info),
						FileCompressionInformation);
	if (NT_SUCCESS(status))
		*csize_ret = info.CompressedFileSize.QuadPart;
	return status;
}

static void
tally_dentry_metadata(const FILE_ID_BOTH_DIR_INFORMATION *info)
{
	if (!inode_seen(info->FileId.QuadPart)) {
		if (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			counters.reparse_points++;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			counters.directories++;
		} else {
			counters.nondirectories++;
			counters.unnamed_data_stream_nominal_size +=
					info->EndOfFile.QuadPart;
			counters.unnamed_data_stream_allocated_size +=
					info->AllocationSize.QuadPart;
		}
	}
}

/* Recursive scan.
 *
 * @cur_dir
 *	Parent directory, or NULL if first iteration.
 * @path
 *	Basename of current file, or the full name if first iteration.
 * @path_nchars
 *	Number of characters valid in @path (will be null-terminated as well).
 * @d_meta
 *	Metadata for this file or directory if available from parent directory,
 *	otherwise NULL.  This will be used if the file itself cannot be opened
 *	due to a sharing violation.
 */
static void
analyze(HANDLE cur_dir, const wchar_t *path, size_t path_nchars,
	const FILE_ID_BOTH_DIR_INFORMATION *d_meta)
{
	HANDLE h;
	NTSTATUS status;
	FILE_ALL_INFORMATION file_info;

	status = open_file(cur_dir, path, path_nchars, &h);

	if (!NT_SUCCESS(status)) {
		if (status == STATUS_SHARING_VIOLATION && d_meta) {
			counters.sharing_violations++;
			counters.sharing_violations_total_size +=
					d_meta->EndOfFile.QuadPart;
			tally_dentry_metadata(d_meta);
			return;
		}
		if (cur_dir == NULL)
			fatal("\"%ls\": Can't open file (%ls)",
			      printable_path(cur_dir, path),
			      nt_error_string(status));
		else
			warn("\"%ls\": Can't open file (%ls)",
			     printable_path(cur_dir, path),
			     nt_error_string(status));
		return;
	}

	if (cur_dir == NULL)
		detect_wof(h);

	status = query_all_file_info(h, &file_info);

	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
		warn("\"%ls\": Can't read metadata (%ls)",
		     handle_to_path(h), nt_error_string(status));
		goto out_close;
	}

	if (inode_seen(file_info.InternalInformation.IndexNumber.QuadPart))
		goto out_close;

	if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		counters.reparse_points++;

	tally_named_data_streams(h);

	if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		counters.directories++;
		recurse_directory(h);
	} else {
		enum backing backing;
		uint64_t wim_id;
		uint8_t resource_hash[RESOURCE_HASH_SIZE];

		counters.nondirectories++;
		counters.unnamed_data_stream_nominal_size +=
			file_info.StandardInformation.EndOfFile.QuadPart;
		counters.unnamed_data_stream_allocated_size +=
			file_info.StandardInformation.AllocationSize.QuadPart;

		backing = get_external_backing(h, &wim_id, resource_hash);
		if (backing & BACKING_EXTERNAL) {
			uint64_t csize;

			counters.externally_backed_files++;
			counters.externally_backed_nominal_size +=
				file_info.StandardInformation.EndOfFile.QuadPart;
			counters.externally_backed_allocated_size +=
				file_info.StandardInformation.AllocationSize.QuadPart;

			if (backing == BACKING_EXTERNAL_WIM)
				tally_perwim_info(wim_id, &file_info);

			if (backing != BACKING_EXTERNAL_WIM ||
			    !resource_seen(wim_id, resource_hash))
			{
				status = query_compressed_size(h, &csize);
				if (NT_SUCCESS(status)) {
					counters.externally_backed_compressed_size += csize;
				} else {
					warn("\"%ls\": Can't query compressed file size (%ls)",
					     handle_to_path(h),
					     nt_error_string(status));
				}
			}
		}
	}

out_close:
	(*func_NtClose)(h);
}

static void
enable_privilege(const wchar_t *privilege)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;

	if (OpenProcessToken(GetCurrentProcess(),
			     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, privilege, &luid)) {
			newState.PrivilegeCount = 1;
			newState.Privileges[0].Luid = luid;
			newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL);
		}
		CloseHandle(hToken);
	}
}

static void
pline(void)
{
	puts("--------------------------------------------------------------------------------");
}

int
wmain(int argc, wchar_t **argv)
{
	wchar_t *fullpath;
	size_t fullpath_nchars;
	const wchar_t *prefix = L"\\??\\";
	const size_t prefix_nchars = wcslen(prefix);
	DWORD ret;

	enable_privilege(SE_BACKUP_NAME);

	init_ntdll();

	if (argc != 2) {
		fprintf(stderr, "This is " PROJECT " version " PROJECT_VERSION"\n");
		fprintf(stderr, "Usage: %ls DIR\n", argv[0]);
		return 2;
	}

	/* Prepare the initial path.  */
	fullpath = xmalloc(32768 * sizeof(wchar_t));

	wcscpy(fullpath, prefix);
	ret = GetFullPathName(argv[1], 32768 - prefix_nchars,
			      fullpath + prefix_nchars, NULL);
	if (ret == 0) {
		fatal("\"%ls\": Can't get full path (%ls)",
		      argv[1], win32_error_string(GetLastError()));
	}
	fullpath_nchars = prefix_nchars + ret;

	/* Scan the directory tree.  */
	pline();
	printf("Analyzing \"%ls\"\n", prettify_path(fullpath));
	analyze(NULL, fullpath, fullpath_nchars, NULL);
	pline();

	/* Print statistics.  */

	printf("Directory count:              %s\n",
	       u64_to_pretty_string(counters.directories));
	printf("Nondirectory count:           %s\n",
	       u64_to_pretty_string(counters.nondirectories));
	printf("Reparse point count:          %s\n",
	       u64_to_pretty_string(counters.reparse_points));
	if (wof_running) {
		printf("Externally backed file count: %s\n",
		       u64_to_pretty_string(counters.externally_backed_files));
	}
	printf("\n");
	if (counters.named_data_streams) {
		printf("Total unnamed data stream nominal size:   %s bytes\n",
		       u64_to_pretty_string(counters.unnamed_data_stream_nominal_size));
		printf("Total unnamed data stream allocated size: %s bytes\n",
		       u64_to_pretty_string(counters.unnamed_data_stream_allocated_size));
		printf("\n");
		printf("Named data stream count:                %s\n",
		       u64_to_pretty_string(counters.named_data_streams));
		printf("Total named data stream nominal size:   %s bytes\n",
		       u64_to_pretty_string(counters.named_data_stream_nominal_size));
		printf("Total named data stream allocated size: %s bytes\n",
		       u64_to_pretty_string(counters.named_data_stream_allocated_size));
	} else {
		printf("Total file contents nominal size:       %s bytes\n",
		       u64_to_pretty_string(counters.unnamed_data_stream_nominal_size));
		printf("Total file contents allocated size:     %s bytes\n",
		       u64_to_pretty_string(counters.unnamed_data_stream_allocated_size));
	}

	if (wof_running && counters.externally_backed_files) {
		uint64_t bytes_saved_1 = 0;
		uint64_t bytes_saved_2 = 0;
		uint64_t nominal_total;

		if (counters.externally_backed_allocated_size <
		    counters.externally_backed_nominal_size)
		{
			bytes_saved_1 = counters.externally_backed_nominal_size -
					counters.externally_backed_allocated_size;
		}

		if (counters.externally_backed_compressed_size < bytes_saved_1)
			bytes_saved_2 = bytes_saved_1 - counters.externally_backed_compressed_size;

		nominal_total = counters.unnamed_data_stream_nominal_size +
				counters.named_data_stream_nominal_size;

		printf("\n");

		printf("Total size saved by external backing:   %s bytes (~%.2f%% savings)\n",
		       u64_to_pretty_string(bytes_saved_1),
		       TO_PERCENT(bytes_saved_1, nominal_total));
		printf("            ... or only %s bytes when accounting for\n"
		       "            %s bytes of compressed data (~%.2f%% savings)\n",
		       u64_to_pretty_string(bytes_saved_2),
		       u64_to_pretty_string(counters.externally_backed_compressed_size),
		       TO_PERCENT(bytes_saved_2, nominal_total));
		printf("\n");

		if (perwim_info_set) {
			struct perwim_info *p;

			printf("Per-WIM statistics:\n");
			avl_tree_for_each_in_order(p, perwim_info_set,
						   struct perwim_info, index_node)
			{
				if (p->counters.nominal_size) {
					printf("    %-30ls backs %-10s bytes in %ls\n",
					       prettify_path(p->wim_path),
					       u64_to_pretty_string(p->counters.nominal_size),
					       prettify_path(fullpath));
				}
			}
		}
	}

	if (counters.sharing_violations) {
		fprintf(stderr,
"\n"
"WARNING: %s files (totaling %s nominal bytes) could not be opened\n"
"         due to sharing violations.  The nominal and allocated sizes of these\n"
"         files were read from their containing directories.  These values are\n"
"         usually correct, but there is no guarantee, since Windows does not\n"
"         keep them updated.  Furthermore, " PROJECT " was unable to query\n"
"         external backing information, named data stream information, or\n"
"         compressed sizes for any of these files.  Therefore, the printed\n"
"         statistics may be inaccurate.  For example, more files may be backed\n"
"         by WIM archives than stated above.\n"
"\n"
"         This is NOT a bug in " PROJECT "!  Analyze your drive offline to\n"
"         avoid these problems.\n",
		u64_to_pretty_string(counters.sharing_violations),
		u64_to_pretty_string(counters.sharing_violations_total_size));
	}

	/* Cleanup and exit.  */
	free(fullpath);
	free_ino_set();
	free_wim_info();

	return 0;
}
