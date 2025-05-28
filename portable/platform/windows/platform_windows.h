/* Windows-specific declarations.

Do not include this file directly. Include "platform.h" instead. */

// Disable Microsoft C runtime library deprecation wwarnings.
#define _CRT_SECURE_NO_WARNINGS

#include <direct.h>  /* _chdir() etc. */
#include <io.h>  /* (is this needed?) */
#include <search.h>  /* _findfirst64(), _findnext64(), _findclose() */
#include <stdlib.h>  /* _MAX_PATH etc.*/
#include <sys/stat.h>  /* struct _stat etc. */
#include <sys/utime.h>  /* _utime(), struct _utimbuf*/

#ifndef S_ISDIR
// _S_IFDIR = 0x4000
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif

#ifndef S_ISREG
// _S_IFREG = 0x8000
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
