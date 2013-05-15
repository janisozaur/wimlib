#ifndef _WIMLIB_ENCODING_H
#define _WIMLIB_ENCODING_H

#include "wimlib/types.h"

extern void
iconv_global_cleanup(void);

extern bool wimlib_mbs_is_utf8;

#define DECLARE_CHAR_CONVERSION_FUNCTIONS(varname1, varname2,		\
					  chartype1, chartype2)		\
									\
extern int								\
varname1##_to_##varname2(const chartype1 *in, size_t in_nbytes,		\
			 chartype2 **out_ret,				\
			 size_t *out_nbytes_ret);			\
									\
extern int								\
varname1##_to_##varname2##_nbytes(const chartype1 *in, size_t in_nbytes,\
				  size_t *out_nbytes_ret);		\
									\
extern int								\
varname1##_to_##varname2##_buf(const chartype1 *in, size_t in_nbytes,	\
			       chartype2 *out);


#if !TCHAR_IS_UTF16LE
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf16le, tstr, utf16lechar, tchar);
DECLARE_CHAR_CONVERSION_FUNCTIONS(tstr, utf16le, tchar, utf16lechar);
#endif

extern int
utf8_to_tstr_simple(const char *utf8str, tchar **out);

extern int
tstr_to_utf8_simple(const tchar *tstr, char **out);

#endif /* _WIMLIB_ENCODING_H */