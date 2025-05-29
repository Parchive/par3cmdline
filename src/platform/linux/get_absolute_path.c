#include "platform_linux.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getcwd() */

/* Resolves a relative path in memory.

The path buffer spans from `begin` to `lim` (exclusive).
`end` must lie between `begin` and `lim` (both inclusive).

Invariant: the array from `begin` to `end` (exclusive) contains a sequence of
nonempty path components each prefixed with exactly one slash, but not zero-
terminated. The root path is represented as an empty string (begin == end).

Example:

    char buf[24] = "/foo/bar/bazXXXXXXXXXXXX"
                    ^           ^           ^
                  begin        end         lim

This function resolves the relative path and returns the final value of `end`,
or NULL if the intermediate path did not fit in memory. */
static char *resolve_path(char *begin, char *end, char *lim, const char *rel)
{
    for (;;) {
        const char *sep = strchr(rel, '/');
        size_t len = sep == NULL ? strlen(rel) : (sep - rel);
        if (len == 0) {
            /* empty component; ignore */
        } else if (len == 1 && rel[0] == '.') {
            /* "." component; ignore */
        } else if (len == 2 && rel[0] == '.' && rel[1] == '.') {
            /* ".." component; move up a directory, unless already at root */
            if (end != begin) do --end; while (*end != '/');
        } else {
            /* regular path component; append */
            if (1 + len > lim - end) return NULL;  /* no space */
            *end++ = '/';
            memcpy(end, rel, len);
            end += len;
        }
        if (sep == NULL) break;
        rel = sep + 1;
    }
    return end;
}

/* assumes lim - begin >= 2 */
static char *abs_path_impl(char *begin, char *lim, const char *rel) {
    char *end = begin;
    if (rel[0] == '/') {
        /* Relative path is actually absolute; start from root. */
        ++rel;
    } else {
        /* Start with the current working directory, assuming it is a regular
           absolute path (i.e., no empty components, no trailing slash). */
        if (getcwd(begin, lim - begin) == NULL) return NULL;
        if (begin[0] != '/') return NULL;  /* invalid path */
        end = begin + strlen(begin);
        if (end == begin + 1) --end;  /* root */
    }
    end = resolve_path(begin, end, lim, rel);
    if (end == NULL || end == lim) return NULL;  /* out of memory */
    if (end == begin) *end++ = '/';  /* root */
    *end++ = '\0';  /* zero-terminate */
    return end;
}

#define ABS_PATH_BUF_SIZE (PATH_MAX * 2)

/* Note: the current implementation only resolves path components. It does not
   resolve symbolic links and does not require that the final path exists! */
int get_absolute_path(char *abs_path, const char *rel_path, size_t max)
{
    if (abs_path == NULL || rel_path == NULL || max < 2) return 1;

    if (max >= ABS_PATH_BUF_SIZE) {
        /* Large output. Resolve directly inside abs_path. */
        char *end = abs_path_impl(abs_path, abs_path + max, rel_path);
        if (end == NULL) return 1;
        return 0;
    } else {
        /* Small output. Use a stack-allocated buffer of size PATH_MAX * 2 to
        work in, because the intermediate path can be longer than the resolved
        path, though the final resolved path cannot be longer than the working
        directory and relative path combined. */
        char buf[ABS_PATH_BUF_SIZE];
        char *end = abs_path_impl(buf, buf + ABS_PATH_BUF_SIZE, rel_path);
        if (end == NULL || end - buf > max) return 1;
        memcpy(abs_path, buf, end - buf);  /* copies zero-terminator */
        return 0;
    }
}
