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

INCLUDES		=  -I$(top_builddir) -I$(top_srcdir) \
			-I /usr/include/libelf

LIBS			= -lelf -lgpgme

bin_PROGRAMS 		= elfpgp
elfpgp_SOURCES 		= main.c sign.c verify.c dump.c elfstrings.c
EXTRA_elfpgp_SOURCES	= options.h sign.h verify.h dump.h \
				debug.h elfhelp.h elfpgp.h \
				elfstrings.h

#CFLAGS		= -O2 -Wall -Werror
CFLAGS		= -O0 -ggdb -Wall -Werror

