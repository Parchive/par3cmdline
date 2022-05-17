##  This file is part of par3cmdline (a PAR 3.0 compatible file verification and
##  repair tool). See https://parchive.github.io/ for details of PAR 3.0.
##
##  Copyright (c) 2003 Peter Brian Clements
##  Copyright (c) 2019 Michael D. Nahas
##  Copyright (c) 2022 Michael D. Nahas
##
##  par3cmdline is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 2 of the License, or
##  (at your option) any later version.
##
##  par3cmdline is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AUTOMAKE_OPTIONS = subdir-objects

.DELETE_ON_ERROR:

noinst_LIBRARIES = libpar3.a
libpar3_a_SOURCES = src/block_check.c \
	src/block_create.c \
	src/block.h \
	src/block_map.c \
	src/common.c \
	src/common.h \
	src/galois8.c \
	src/galois.h \
	src/hash.c \
	src/hash.h \
	src/libpar3.c \
	src/libpar3_create.c \
	src/libpar3.h \
	src/libpar3_verify.c \
	src/map.c \
	src/map.h \
	src/map_simple.c \
	src/map_slide.c \
	src/packet_add.c \
	src/packet.h \
	src/packet_make.c \
	src/packet_parse.c \
	src/read.c \
	src/read.h \
	src/reedsolomon.c \
	src/reedsolomon.h \
	src/repair.c \
	src/repair.h \
	src/verify.c \
	src/verify_check.c \
	src/verify.h \
	src/write.c \
	src/write.h \
	src/write_trial.c \
	src/blake3/blake3.h \
	src/blake3/blake3_impl.h \
	src/blake3/blake3.c \
	src/blake3/blake3_portable.c


bin_PROGRAMS = par3
man_MANS = man/par3.1

par3_SOURCES = src/main.c \
	src/common.h \
	src/common.c
par3_LDADD = libpar3.a

AM_CXXFLAGS = -Wall 


install-exec-hook :
	cd $(DESTDIR)$(bindir)/ && \
	ln -sf par3$(EXEEXT) par3create$(EXEEXT) && \
	ln -sf par3$(EXEEXT) par3verify$(EXEEXT) && \
	ln -sf par3$(EXEEXT) par3repair$(EXEEXT)

uninstall-hook :
	rm -f $(DESTDIR)$(bindir)/par3create$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/par3verify$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/par3repair$(EXEEXT)

