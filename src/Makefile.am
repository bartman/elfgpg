

INCLUDES		=  -I$(top_builddir) -I$(top_srcdir) \
			-I /usr/include/libelf

LIBS			= -lelf -lgpgme

bin_PROGRAMS 		= elfpgp
elfpgp_SOURCES 		= main.c sign.c verify.c
EXTRA_elfpgp_SOURCES	= options.h sign.h verify.h debug.h elfhelp.h elfpgp.h

elfpgp_CFLAGS		= -ggdb

