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
#include "sha1.h"

/*****************************************************************************/

/* Size of WIM resource (stream) hash fields  */
#define RESOURCE_HASH_SIZE 20

/* Useful macros  */
#define ARRAY_LEN(A) (sizeof(A) / sizeof((A)[0]))

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

#ifndef STATUS_OBJECT_NOT_EXTERNALLY_BACKED
#  define STATUS_OBJECT_NOT_EXTERNALLY_BACKED 0xC000046D
#endif

/*****************************************************************************/

/* Global counters, updated during the directory tree scan  */
static struct {
	uint64_t errors;
	uint64_t sharing_violations;
	uint64_t directories;
	uint64_t nondirectories;
	uint64_t externally_backed_files;
	uint64_t bytes_checksummed;
	uint64_t next_bytes_checksummed_progress;
	uint64_t checksum_mismatches;
} counters;

#define BYTES_PER_PROGRESS 100000000

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
	static wchar_t buf[1024];
	wsprintf(buf, L"status 0x%08x: %ls",
		 (uint32_t)status, win32_error_string(func_RtlNtStatusToDosError(status)));
	return buf;
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
static void __attribute__((format(printf, 1, 2)))
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
static void __attribute__((format(printf, 1, 2)))
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

static bool
checksum_file(HANDLE h, uint64_t expected_size, uint8_t hash[RESOURCE_HASH_SIZE])
{
	uint8_t buf[32768];
	DWORD bytesRead;
	SHA_CTX ctx;
	uint64_t actual_size = 0;

	sha1_init(&ctx);
	for (;;) {
		if (!ReadFile(h, buf, sizeof(buf), &bytesRead, NULL)) {
			warn("Error reading \"%ls\": %ls",
			     handle_to_path(h), win32_error_string(GetLastError()));
			counters.errors++;
			return false;
		}
		if (bytesRead == 0)
			break;

		sha1_update(&ctx, buf, bytesRead);
		actual_size += bytesRead;
	}

	sha1_final(hash, &ctx);
	counters.bytes_checksummed += actual_size;
	if (actual_size != expected_size) {
		warn("Actual file size (%s) does not match expected file size (%s): \"%ls\"",
		     u64_to_pretty_string(actual_size),
		     u64_to_pretty_string(expected_size),
		     handle_to_path(h));
	}
	if (counters.bytes_checksummed > counters.next_bytes_checksummed_progress) {
		printf("%s MB checksummed...\n",
		       u64_to_pretty_string(counters.next_bytes_checksummed_progress / 1000000));
		counters.next_bytes_checksummed_progress += BYTES_PER_PROGRESS;
	}

	return true;
}

/* Given an open handle to any file on the volume being scanned, detect if the
 * WOF driver is available.  If not, print an error message and abort.  */
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
		return;
	}

	fatal("\"%ls\": The Windows Overlay File System Filter is not running.",
	      handle_to_path(h));
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
		counters.errors++;
		return BACKING_UNKNOWN;
	}

	if (iosb.Information < sizeof(struct wof_external_info)) {
		warn("\"%ls\": weird results from FSCTL_GET_EXTERNAL_BACKING",
		     handle_to_path(h));
		counters.errors++;
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
verify(HANDLE cur_dir, const wchar_t *path, size_t path_nchars);

static void
recurse_directory(HANDLE h)
{
	uint8_t *buf;
	const size_t bufsize = 32768;
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	buf = xmalloc(bufsize + sizeof(wchar_t));

	while (NT_SUCCESS(status = (*func_NtQueryDirectoryFile)(h, NULL, NULL, NULL,
								&iosb, buf, bufsize,
								FileNamesInformation,
								FALSE, NULL, FALSE)))
	{
		FILE_NAMES_INFORMATION *info;

		info = (FILE_NAMES_INFORMATION *)buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				wchar_t save = info->FileName[info->FileNameLength /
								sizeof(wchar_t)];

				info->FileName[info->FileNameLength /
							sizeof(wchar_t)] = L'\0';

				verify(h, info->FileName,
				       info->FileNameLength / sizeof(wchar_t));

				info->FileName[info->FileNameLength /
							sizeof(wchar_t)] = save;
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (FILE_NAMES_INFORMATION *)
					((uint8_t *)info + info->NextEntryOffset);
		}
	}

	free(buf);
	if (status != STATUS_NO_MORE_FILES) {
		warn("\"%ls\": Can't read directory (%ls)",
		     handle_to_path(h), nt_error_string(status));
		counters.errors++;
	}
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
				  FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
				  &attr,
				  &iosb,
				  FILE_SHARE_VALID_FLAGS,
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
verify(HANDLE cur_dir, const wchar_t *path, size_t path_nchars)
{
	HANDLE h;
	NTSTATUS status;
	FILE_ALL_INFORMATION file_info;

	status = open_file(cur_dir, path, path_nchars, &h);

	if (!NT_SUCCESS(status)) {
		if (status == STATUS_SHARING_VIOLATION) {
			counters.sharing_violations++;
		} else {
			if (cur_dir == NULL) {
				fatal("\"%ls\": Can't open file (%ls)",
				      printable_path(cur_dir, path),
				      nt_error_string(status));
			}
			warn("\"%ls\": Can't open file (%ls)",
			     printable_path(cur_dir, path),
			     nt_error_string(status));
		}
		counters.errors++;
		return;
	}

	if (cur_dir == NULL)
		detect_wof(h);

	status = query_all_file_info(h, &file_info);

	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
		warn("\"%ls\": Can't read metadata (%ls)",
		     handle_to_path(h), nt_error_string(status));
		counters.errors++;
		goto out_close;
	}

	if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		counters.directories++;
		recurse_directory(h);
	} else {
		enum backing backing;
		uint64_t wim_id;
		uint8_t resource_hash[RESOURCE_HASH_SIZE];
		uint8_t actual_hash[RESOURCE_HASH_SIZE];

		counters.nondirectories++;

		backing = get_external_backing(h, &wim_id, resource_hash);

		if (backing & BACKING_EXTERNAL) {
			counters.externally_backed_files++;
			if (backing == BACKING_EXTERNAL_WIM) {
				if (checksum_file(h,
						  file_info.StandardInformation.EndOfFile.QuadPart,
						  actual_hash))
				{
					if (memcmp(resource_hash, actual_hash, RESOURCE_HASH_SIZE)) {
						warn("CHECKSUM MISMATCH: path=\"%ls\"", handle_to_path(h));
						counters.checksum_mismatches++;
					}
				}
			} else {
				warn("Ignoring \"%ls\": externally backed, but not by WIM archive",
				     handle_to_path(h));
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

	counters.next_bytes_checksummed_progress = BYTES_PER_PROGRESS;

	/* Scan the directory tree.  */
	pline();
	printf("Verifying \"%ls\"\n", prettify_path(fullpath));
	verify(NULL, fullpath, fullpath_nchars);
	pline();

	/* Print statistics.  */

	printf("Errors: %s (%s were sharing violations)\n",
	       u64_to_pretty_string(counters.errors),
	       u64_to_pretty_string(counters.sharing_violations));
	printf("File counts: %s dirs, %s nondirs (%s externally backed)\n",
	       u64_to_pretty_string(counters.directories),
	       u64_to_pretty_string(counters.nondirectories),
	       u64_to_pretty_string(counters.externally_backed_files));
	printf("%s bytes checksummed; %s mismatches\n",
	       u64_to_pretty_string(counters.bytes_checksummed),
	       u64_to_pretty_string(counters.checksum_mismatches));
	printf("\n");

	/* Cleanup and exit.  */
	free(fullpath);

	return 0;
}
