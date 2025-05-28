#include "locale_helpers.h"

#include <locale.h>
#include <string.h>

/* Determines whether the locale name includes the UTF-8 codeset.

A locale name is of the form: language[_territory][.codeset][@modifier]
"UTF-8" may be of written in any case and the hyphen is optional.

Returns 1 if it is UTF-8, or 0 if it is not. */
static int locale_is_utf8(char *locale) {
    if (locale == NULL) return 0;
    const char *p = strchr(locale, '.');
    if (p == NULL) return 0;
    ++p;
    if (*p != 'U' && *p != 'u') return 0; else ++p;
    if (*p != 'T' && *p != 't') return 0; else ++p;
    if (*p != 'F' && *p != 'f') return 0; else ++p;
    if (*p == '-') ++p; /* optional */
    if (*p != '8') return 0; else ++p;
    return *p == '\0' || *p == '@';
}

/* Returns 1 if the CTYPE locale uses a UTF-8 codeset, 0 if not. */
int ctype_is_utf8() {
    return locale_is_utf8(setlocale(LC_CTYPE, NULL));
}

/* Tries to change the CTYPE part of the locale to a UTF-8 codeset.
   Returns 0 on success or -1 on failure. */
int ctype_set_utf8() {
    /* Attempt 1: set from the environment (which is preferred) */
    char *locale = setlocale(LC_CTYPE, "");
    if (locale_is_utf8(locale)) return 0;  /* already UTF-8 */

    /* Attempt 2: this works on Windows, but not on Linux. */
    if (setlocale(LC_CTYPE, ".UTF-8") != NULL) return 0;

    /* Attempt 3: keep the language setting, but change codeset
       (this also removes modifiers like @euro; oh well, too bad) */
    if (locale != NULL) {
        const char *p = strchr(locale, '.');
        if (p != NULL) {
            size_t n = p - locale;
            if (n <= 56) {
                char buf[64];
                memcpy(buf, locale, n);
                strcpy(buf + n, ".UTF-8");
                if (setlocale(LC_CTYPE, buf) != NULL) return 0;
            }
        }
    }

    /* Attempt 4: change the locale to C.UTF-8. This should work on
       all systems that support UTF-8 at all. */
    if (setlocale(LC_CTYPE, "C.UTF-8") != NULL) return 0;

    return -1;  /* Nothing worked! Return failure. */
}
