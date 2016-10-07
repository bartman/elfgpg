# Copyright (C) 2001-2003 Bart Trojanowski <bart@jukie.net>
#
# This file is a part of the elfsign utility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

#ident "%Z%%M% %I%      %E% Bart Trojanowski <bart@jukie.net>"

INCLUDES		=  -I$(top_builddir)/src -I$(top_srcdir)/src \
			-I$(top_builddir)/lib -I$(top_srcdir)/lib \
			-I /usr/include/libelf

LIBS			= -lelf -lgpgme -lgpg-error

bin_PROGRAMS 		= elfgpg
elfgpg_SOURCES 		= main.c sign.c verify.c dump.c elfstrings.c
EXTRA_elfgpg_SOURCES	= options.h sign.h verify.h dump.h \
				debug.h elfhelp.h elfgpg.h \
				elfstrings.h

AM_CFLAGS		= -O2 -Wall -Werror
#AM_CFLAGS		= -O0 -ggdb -Wall -Werror

