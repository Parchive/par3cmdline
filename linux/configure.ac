dnl  This file is part of par3cmdline (a PAR 3.0 compatible file verification and
dnl  repair tool). See https://parchive.github.io/ for details of PAR 3.0.
dnl
dnl  Copyright (c) 2003-2015 Peter Brian Clements
dnl  Copyright (c) 2011-2012 Marcel Partap
dnl  Copyright (c) 2012-2015 Ike Devolder
dnl  Copyright (c) 2019-2022 Michael D. Nahas
dnl
dnl  par3cmdline is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  par3cmdline is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program; if not, write to the Free Software
dnl  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([par3cmdline], [0.0.1], [par3@mike.nahasmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/main.c])

AC_CANONICAL_HOST

dnl disable SIMD for MinGW
case "$host" in
     *-*-mingw*)
       CFLAGS="$CFLAGS -DBLAKE3_NO_AVX512"
       CFLAGS="$CFLAGS -DBLAKE3_NO_SSE41"
       CFLAGS="$CFLAGS -DBLAKE3_NO_SSE2"
       ;;
     *)
       ;;
esac

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE


dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

dnl Need to define RANLIB used in making static library.
AC_PROG_RANLIB
dnl gnu.org says the following may be needed for Microsoft libraries.
AM_PROG_AR

dnl ChatGPT recommended these when I added C++ code
dnl Check for the C++ compiler
AM_CONDITIONAL([HAVE_CXX], [test "$CXX" != "no"])
dnl Set C++ compiler flags
AC_SUBST([CXXFLAGS])

dnl Set language to C
AC_LANG(C)


dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDBOOL
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h] [endian.h])
AC_CHECK_HEADERS([getopt.h] [limits.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_C_BIGENDIAN
AC_C_CONST
AC_C_INLINE
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([stricmp] [strcasecmp])
AC_CHECK_FUNCS([strchr] [memcpy])

AC_CHECK_FUNCS([getopt] [getopt_long])

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

