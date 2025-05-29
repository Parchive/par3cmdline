#include "platform_linux.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Maximum recursion depth when pattern matching. Recursion depth is determined
   by the number of asterisks in `pattern`, which should normally be small. */
#define PATTERN_MATCH_MAX_DEPTH 100

/* Recursive implementation of pattern_match().
   See pattern_match(), defined below, for details. */
static int pattern_match_impl(
        const char *p_begin, const char *p_end, mbstate_t *p_state,
        const char *t_begin, const char *t_end, mbstate_t *t_state,
        int depth_left) {
    while (p_begin < p_end) {
        size_t ps = mbrlen(p_begin, p_end - p_begin, p_state);
        char wildcard = ps == 1 ? *p_begin : '\0';
        if (ps < 1 || ps > p_end - p_begin) ps = 1;  /* skip invalid */

        if (wildcard == '?') {
            /* Match any single character. */
            p_begin += ps;
            if (t_begin == t_end) return 0;  /* no match */
            size_t ts = mbrlen(t_begin, t_end - t_begin, t_state);
            if (ts < 1 || ts > t_end - t_begin) ts = 1;  /* skip invalid */
            t_begin += ts;
        } else if (wildcard == '*') {
            /* Match any number of characters. */
            p_begin += ps;
            if (p_begin == p_end) return 1;  /* any suffix matches */
            if (depth_left == 0) return -1;  /* no more recursion allowed */
            for (;;) {
                mbstate_t new_p_state = *p_state;
                mbstate_t new_t_state = *t_state;
                int res = pattern_match_impl(
                        p_begin, p_end, &new_p_state,
                        t_begin, t_end, &new_t_state,
                        depth_left - 1);
                if (res != 0) return res;  /* either a match, or an error */
                if (t_begin == t_end) return 0;  /* no match */
                size_t ts = mbrlen(t_begin, t_end - t_begin, t_state);
                if (ts < 1 || ts > t_end - t_begin) ts = 1;  /* skip invalid */
                t_begin += ts;
            }
        } else {
            if (t_begin == t_end) return 0;  /* no match */
            size_t ts = mbrlen(t_begin, t_end - t_begin, t_state);
            if (ts < 1 || ts > t_end - t_begin) ts = 1;  /* skip invalid */
            if (ps != ts || memcmp(p_begin, t_begin, ps) != 0)
                return 0;  /* no match! */
            p_begin += ps;
            t_begin += ts;
        }
    }
    if (t_begin == t_end) return 1;  /* match! */
    return 0;  /* no match */
}

/* Tries to match the given `target` string against the `pattern` and
returns 1 if they match, 0 if they don't, or -1 on error.

This function is multibyte-aware, so e.g. '?' matches exactly one UTF-8 code
sequence rather than one byte. Otherwise, comparisons are done on the byte level
(e.g. equivalent characters that are encoded in a different way do not match.)

The pattern consists of literal characters, and two types of wildcards:
question marks ('?') which match any single character, and asterisks ('*')
which match any number of characters (including zero).

The current implementation takes time O(|pattern| × |target|) in the worst
case, which is not great, but in practice it's not really an issue because
targets are filenames which are limited to about 256 bytes, and patterns are
user-supplied, so typically they aren't too long either.
*/
static int pattern_match(const char *pattern, const char *target) {
    /* TODO: validate the pattern up front, and create fast paths
       for the common cases where pattern contains no wildcards (in which
       case we can simply do strcmp()) or only a single asterisk wildcard
       (in which case we only need to match prefix/suffix). */
    /* TODO: support for escaping? Currently it's impossible to match
       a filename that is literally "*" without matching all files. */
    mbstate_t pattern_state;
    mbstate_t target_state;
    memset(&pattern_state, 0, sizeof pattern_state);
    memset(&target_state, 0, sizeof target_state);
    size_t pattern_len = strlen(pattern);
    size_t target_len  = strlen(target);
    int res = pattern_match_impl(
        pattern, pattern + pattern_len, &pattern_state,
        target,  target  + target_len,  &target_state,
        PATTERN_MATCH_MAX_DEPTH);
    return res;
}

struct findstate {
    DIR *dir;
    char *pattern;
};

static int free_findstate(struct findstate *fs) {
    if (fs == NULL) return 0;
    DIR *dir = fs->dir;
    free(fs->pattern);
    free(fs);
    if (dir != NULL && closedir(dir) != 0) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

static struct findstate *handle_to_findstate(intptr_t handle) {
    if (handle == 0 || handle == -1) {
        errno = EINVAL;
        return NULL;
    }
    return (void*)handle;
}

static int findnext_impl(struct findstate *fs, struct _finddatai64_t *fileinfo) {
    if (fs == NULL || fileinfo == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct dirent *de;
    do {
        errno = 0;
        if ((de = readdir(fs->dir)) == NULL) {
            /* According to the Microsoft documentation, ENOENT signals no more
               matches. EINVAL signals invalid arguments, but also that
               "the operating system returned an unexpected error". */
            errno = (errno == 0 ? ENOENT : EINVAL);
            return -1;
        }
    } while (pattern_match(fs->pattern, de->d_name) != 1);

    size_t namelen = strlen(de->d_name);
    if (namelen > NAME_MAX) {
        errno = ENOMEM;
        return -1;
    }
    /* Copy filename into fileinfo struct: */
    memcpy(fileinfo->name, de->d_name, namelen);
    fileinfo->name[namelen] = '\0';

    struct stat st;
    if (fstatat(dirfd(fs->dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }

    /* Fill in rest of fileinfo struct: */
    fileinfo->attrib =
        S_ISREG(st.st_mode) ? _A_NORMAL :
        S_ISDIR(st.st_mode) ? _A_SUBDIR : _A_SYSTEM;
    if (de->d_name[0] == '.') {
        fileinfo->attrib |= _A_HIDDEN;
    }
    fileinfo->time_create = st.st_ctim.tv_sec;
    fileinfo->time_access = st.st_atim.tv_sec;
    fileinfo->time_write  = st.st_mtim.tv_sec;
    fileinfo->size        = st.st_size;
    return 0;
}

intptr_t _findfirst64(const char *filespec, struct _finddatai64_t *fileinfo) {
    DIR *dir;
    const char *dirsep = strrchr(filespec, '/');
    if (dirsep == NULL) {
        /* No directory separator. Open current working directory. */
        dir = opendir(".");
        if (dir == NULL) {
            errno = ENOENT;
            return -1;
        }
    } else {
        /* Directory separator found. Open specified directory. */
        size_t dirname_len = dirsep - filespec;
        char *dirname = malloc(dirname_len + 1);
        if (dirname == NULL) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(dirname, filespec, dirname_len);
        dirname[dirname_len] = '\0';
        dir = opendir(dirname);
        free(dirname);
        if (dir == NULL) {
            errno = ENOENT;
            return -1;
        }
    }

    char *pattern = strdup(dirsep == NULL ? filespec : dirsep + 1);
    if (pattern == NULL) {
        closedir(dir);  /* ignore error */
        errno = ENOMEM;
        return -1;
    }

    struct findstate *fs = malloc(sizeof *fs);
    if (fs == NULL) {
        closedir(dir);  /* ignore error */
        free(pattern);
        errno = ENOMEM;
        return -1;
    }

    fs->dir = dir;
    fs->pattern = pattern;
    if (findnext_impl(fs, fileinfo) != 0) {
        free_findstate(fs);
        return -1;
    }
    return (intptr_t) fs;
}

int _findnext64(intptr_t handle, struct _finddatai64_t *fileinfo) {
    int res = findnext_impl(handle_to_findstate(handle), fileinfo);
    return res;
}

int _findclose(intptr_t handle) {
    return free_findstate(handle_to_findstate(handle));
}
