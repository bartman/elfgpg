## $Id: Makefile.am,v 1.1.1.1 2001/07/10 00:20:13 bartron Exp $

INCLUDES		=  -I$(top_builddir) -I$(top_srcdir) \
			-I /usr/include/libelf

LIBS			= -lelf -lgpgme

bin_PROGRAMS 		= elfpgp
elfpgp_SOURCES 		= main.c sign.c verify.c
EXTRA_elfpgp_SOURCES	= options.h sign.h verify.h debug.h elfhelp.h elfpgp.h

#CFLAGS		= -O2 -Wall -Werror
CFLAGS		= -O0 -ggdb -Wall -Werror

