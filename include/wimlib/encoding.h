#ifndef _WIMLIB_ENCODING_H
#define _WIMLIB_ENCODING_H

#include <string.h>

#include "wimlib/error.h"
#include "wimlib/util.h"
#include "wimlib/types.h"

extern int
utf8_to_utf16le(const char *in, size_t in_nbytes,
		utf16lechar **out_ret, size_t *out_nbytes_ret);

extern int
utf16le_to_utf8(const utf16lechar *in, size_t in_nbytes,
		char **out_ret, size_t *out_nbytes_ret);

static inline int
tstr_to_tstr(const tchar *in, size_t in_nbytes,
	     tchar **out_ret, size_t *out_nbytes_ret)
{
	*out_ret = MALLOC(in_nbytes + sizeof(tchar));
	if (unlikely(!*out_ret))
		return WIMLIB_ERR_NOMEM;
	memcpy(*out_ret, in, in_nbytes);
	(*out_ret)[in_nbytes / sizeof(tchar)] = 0;
	if (out_nbytes_ret)
		*out_nbytes_ret = in_nbytes;
	return 0;
}

#if TCHAR_IS_UTF16LE

/* tstr(UTF-16LE) <=> UTF-16LE  */
#  define tstr_to_utf16le	tstr_to_tstr
#  define utf16le_to_tstr	tstr_to_tstr

/* tstr(UTF-16LE) <=> UTF-8  */
#  define tstr_to_utf8		utf16le_to_utf8
#  define utf8_to_tstr		utf8_to_utf16le

#else

/* tstr(UTF-8) <=> UTF-16LE  */
#  define tstr_to_utf16le	utf8_to_utf16le
#  define utf16le_to_tstr	utf16le_to_utf8

/* tstr(UTF-8) <=> UTF-8  */
#  define tstr_to_utf8		tstr_to_tstr
#  define utf8_to_tstr		tstr_to_tstr

#endif

/* Convert a string in the platform-dependent encoding to UTF-16LE, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * tstr_put_utf16le() when done.  */
static inline int
tstr_get_utf16le_and_len(const tchar *tstr,
			 const utf16lechar **ustr_ret, size_t *usize_ret)
{
	size_t tsize = tstrlen(tstr) * sizeof(tchar);
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*ustr_ret = tstr;
	*usize_ret = tsize;
	return 0;
#else
	return tstr_to_utf16le(tstr, tsize, (utf16lechar **)ustr_ret, usize_ret);
#endif
}

/* Convert a string in the platform-dependent encoding to UTF-16LE, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * tstr_put_utf16le() when done.  */
static inline int
tstr_get_utf16le(const tchar *tstr, const utf16lechar **ustr_ret)
{
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*ustr_ret = tstr;
	return 0;
#else
	size_t tsize = tstrlen(tstr) * sizeof(tchar);
	return tstr_to_utf16le(tstr, tsize, (utf16lechar **)ustr_ret, NULL);
#endif
}

/* Release a string acquired with tstr_get_utf16le() or
 * tstr_get_utf16le_and_len().  */
static inline void
tstr_put_utf16le(const utf16lechar *ustr)
{
#if !TCHAR_IS_UTF16LE
	FREE((void *)ustr);
#endif
}

/* Convert a UTF16-LE string to the platform-dependent encoding, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * utf16le_put_tstr() when done.  */
static inline int
utf16le_get_tstr(const utf16lechar *ustr, size_t usize,
		 const tchar **tstr_ret, size_t *tsize_ret)
{
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*tstr_ret = ustr;
	if (tsize_ret)
		*tsize_ret = usize;
	return 0;
#else
	return utf16le_to_tstr(ustr, usize, (tchar **)tstr_ret, tsize_ret);
#endif
}

/* Release a string acquired with utf16le_get_tstr().  */
static inline void
utf16le_put_tstr(const tchar *tstr)
{
#if !TCHAR_IS_UTF16LE
	FREE((void *)tstr);
#endif
}


/* UTF-16LE utility functions  */

extern u16 upcase[65536];

extern void
init_upcase(void);

extern int
cmp_utf16le_strings(const utf16lechar *s1, size_t n1,
		    const utf16lechar *s2, size_t n2,
		    bool ignore_case);

extern int
cmp_utf16le_strings_z(const utf16lechar *s1, const utf16lechar *s2,
		      bool ignore_case);

extern utf16lechar *
utf16le_dupz(const void *ustr, size_t usize);

extern utf16lechar *
utf16le_dup(const utf16lechar *s);

extern size_t
utf16le_len_bytes(const utf16lechar *s);

extern size_t
utf16le_len_chars(const utf16lechar *s);

#endif /* _WIMLIB_ENCODING_H */
