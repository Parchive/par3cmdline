/* Linux-specific declarations.

These are likely close to working on other operating systems in the UNIX
family, such as FreeBSD or OS X, but I haven't been able to verify it.

Do not include this file directly. Include "platform.h" instead. */


/* Request 64-bit off_t and time_t even on 32-bit systems.
These must be defined before any header files are included! */
#define _FILE_OFFSET_BITS 64
#define _TIME_BITS 64

#define _DEFAULT_SOURCE

#include <linux/limits.h>  /* PATH_MAX etc. */
#include <sys/stat.h>   /* struct stat */
#include <sys/types.h>  /* off_t */

#include <limits.h>  /* UINT_MAX etc. */
#include <strings.h>  /* strcasecmp() etc. */
#include <stdio.h>  /* fseeko() etc.*/
#include <time.h>  /* time_t */
#include <unistd.h>  /* ftruncate() */
#include <utime.h>  /* utime(), struct utimbuf */

#define _strnicmp strncasecmp
#define _stricmp strcasecmp

#define _MAX_FNAME  NAME_MAX
#define _MAX_PATH   PATH_MAX
#define _MAX_DIR    PATH_MAX

#define _S_IWRITE S_IWUSR

#define _chdir      chdir
#define _chmod      chmod
#define _chsize_s   ftruncate
#define _ctime64    ctime
#define _fileno     fileno
#define _ftelli64   ftello
#define _fseeki64   fseeko
#define _getcwd     getcwd
#define _stat64     stat
#define _utimbuf    utimbuf
#define _utime      utime

#ifndef __time64_t
#define __time64_t time_t
#endif

#define _mkdir(dirname) mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR)

/* Definitions related to _findfirst64(), _findnext64() and _findclose() follow.

These functions are reimplemented to match the Windows API, but because there
are some concepts that do not map directly from POSIX to Windows, there are some
differences.

Of the file attributes only NORMAL, HIDDEN, SYSTEM and SUBDIR are used.
The HIDDEN attribute is set if the filename starts with a dot.
The SYSTEM attribute is set if the file is neither a regular file nor a
directory. This includes FIFOs, device nodes, etc. but importantly it also
includes symlinks!

To avoid infinite recursion, symlinks are NOT followed. A symlink to a directory
will be listed as a file with a SYTEM attribute, not a SUBDIR.

Hardlinks are indistinguishable from regular files through this API.
*/

/* Windows file attributes. */
#define _A_NORMAL       0x00
#define _A_RDONLY       0x01  /* currently not set */
#define _A_HIDDEN       0x02
#define _A_SYSTEM       0x04
#define _A_SUBDIR       0x10
#define _A_ARCH         0x20

struct _finddatai64_t {
    /* Bitmask of file attributes defined above. */
    unsigned   attrib;

    /* File timestamps, unfortunately truncated to seconds. */
    time_t     time_create;
    time_t     time_access;
    time_t     time_write;

    /* File size. */
    off_t      size;

    /* File name. */
    char name[NAME_MAX + 1];
};
