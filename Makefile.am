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

AUX_DIST                = $(ac_aux_dir)/install-sh \
			$(ac_aux_dir)/missing \
			$(ac_aux_dir)/mkinstalldirs

AUX_DIST_EXTRA          = 
                        

EXTRA_DIST              = autogen.sh

#AUTOMAKE_OPTIONS        = foreign
SUBDIRS                 = src
MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure config-h.in \
			stamp-h.in $(AUX_DIST)

ACLOCAL                 = aclocal -I $(ac_aux_dir)


dist-hook:
	(cd $(distdir) && mkdir $(ac_aux_dir))
	for file in $(AUX_DIST) $(AUX_DIST_EXTRA); do \
	  cp $$file $(distdir)/$$file; \
	done


