/* Defines functions that have platform-specific implementations.

Include this file in each source file that uses platform-specific features.
It will automatically include definitions from the correct platform
subdirectory.

IMPORTANT: this file must be included before standard header files, because
platforms may define macros that affect which definitions are made available
from standard library headers (e.g. _FILE_OFFSET_BITS=64 to ensure off_t is a
64-bit type). */

#ifndef PAR3_PLATFORM_PLATFORM_H_INCLUDED
#define PAR3_PLATFORM_PLATFORM_H_INCLUDED

#if defined(__linux__)
#include "linux/platform_linux.h"
#elif defined(_WIN32)
#include "windows/platform_windows.h"
#else
#error "Unsupported platform (add it?)"
#endif

#include <stddef.h>
#include <stdint.h>

/* Resolves `relative_path` to the current working directory.

Path components like ".." and "." are resolved and removed.

On success, the zero-terminated absolute path is written to `absolute_path`,
which must be at least `max` bytes long, and 0 is returned.

On failure, including when the result does not fit in `absolute_path`,
a nonzero value is returned instead. */
int get_absolute_path(char *absolute_path, const char *relative_path, size_t max);

#ifndef _WIN32  /* avoid conflicting definitions */

/* Returns the length of a file identified by an open file descriptor. */
int64_t _filelengthi64(int fd);

/* File search functions. For documentation, see:
https://learn.microsoft.com/en-us/cpp/c-runtime-library/filename-search-functions
*/
struct _finddatai64_t;
intptr_t _findfirst64(const char *filespec, struct _finddatai64_t *fileinfo);
int _findnext64(intptr_t handle, struct _finddatai64_t *fileinfo);
int _findclose(intptr_t handle);

#endif  /* ndef _WIN32 */

#endif  /* ndef PAR3_PLATFORM_PLATFORM_H_INCLUDED */
