

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


