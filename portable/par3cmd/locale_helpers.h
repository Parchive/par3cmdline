#ifndef PAR3_LOCALE_HELPERS_H_INCLUDED
#define PAR3_LOCALE_HELPERS_H_INCLUDED

/* Returns 1 if the CTYPE locale uses a UTF-8 codeset, 0 if not. */
int ctype_is_utf8();

/* Tries to change the CTYPE part of the locale to a UTF-8 codeset.
   Returns 0 on success or -1 on failure. */
int ctype_set_utf8();

#endif  /* ndef PAR3_LOCALE_HELPERS_H_INCLUDED */
