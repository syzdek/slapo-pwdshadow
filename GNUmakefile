#
#   OpenLDAP pwdPolicy/shadowAccount Overlay
#   Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
#   All rights reserved.
#
#   Dominus vobiscum. Et cum spiritu tuo.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted only as authorized by the OpenLDAP
#   Public License.
#
#   A copy of this license is available in the file LICENSE in the
#   top-level directory of the distribution or, alternatively, at
#   <http://www.OpenLDAP.org/license.html>.
#

RELEASEDATE		= 2023/04/30
PKGVERSION		= 0.0
LTVERSION		= 0:0:0

OPENLDAP_VERSION	?= 2.5.14
OPENLDAP_DOWNLOAD	?= https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-$(OPENLDAP_VERSION).tgz


LIBTOOL			?= libtool
INSTALL			?= /usr/bin/install
CC			?= gcc
CFLAGS_EXTRA		+= -g -O2 -W -Wall -Wextra -Wno-unknown-pragmas
CPPFLAGS_EXTRA		+= -I../../../include \
			   -I../../../servers/slapd \
			   -DSLAPD_OVER_PWDSHADOW=SLAPD_MOD_DYNAMIC
LDFLAGS_EXTRA		+=
NUMJOBS			?= 4

prefix			?= /usr/local
exec_prefix		?= $(prefix)
libdir			?= $(exec_prefix)/lib
libexecdir		?= $(exec_prefix)/libexec
moduledir		?= $(libexecdir)/openldap
mandir			?= $(exec_prefix)/share/man
man5dir			?= $(mandir)/man5
sysconfdir		?= $(prefix)/etc/openldap


TEST_TARGET		= openldap/pwdshadow-$(OPENLDAP_VERSION)
TEST_FILES		= openldap/contrib/slapd-modules/pwdshadow/GNUmakefile \
			  openldap/contrib/slapd-modules/pwdshadow/pwdshadow.c \
			  openldap/contrib/slapd-modules/pwdshadow/pwdshadow.h \
			  openldap/contrib/slapd-modules/pwdshadow/docs/slapo-pwdshadow.5.in


.PHONY: all clean distclean install test-env test-env-install uninstall html


.SUFFIXES: .c .o .lo


all: pwdshadow.la docs/slapo-pwdshadow.5


docs/slapo-pwdshadow.5: docs/slapo-pwdshadow.5.in
	rm -f $(@)
	sed \
	   -e 's,RELEASEDATE,$(RELEASEDATE),g' \
	   -e 's,LDVERSION,$(PKGVERSION),g' \
	   -e 's,ETCDIR,$(sysconfdir),g' \
	   docs/slapo-pwdshadow.5.in \
	   > $(@)
	touch $(@)


pwdshadow.lo: pwdshadow.c pwdshadow.h
	rm -f $(@)
	$(LIBTOOL) --tag=CC --mode=compile $(CC) $(CFLAGS) $(CFLAGS_EXTRA) \
	   $(CPPFLAGS) $(CPPFLAGS_EXTRA) -o pwdshadow.lo -c pwdshadow.c


pwdshadow.la: pwdshadow.lo
	rm -f $(@)
	$(LIBTOOL) --tag=CC --mode=link $(CC) $(LDFLAGS) $(LDFLAGS_EXTRA) \
	   -version-info $(LTVERSION) \
	   -rpath $(moduledir) -module -o pwdshadow.la pwdshadow.lo


test-env: $(TEST_FILES)
	make -C openldap/contrib/slapd-modules/pwdshadow prefix=/tmp/openldap


test-env-install: test-env $(TEST_TARGET)-install
	make -C openldap/contrib/slapd-modules/pwdshadow prefix=/tmp/openldap install
	$(INSTALL) -m 644 docs/slapd.conf-test /tmp/openldap/etc/openldap


openldap-$(OPENLDAP_VERSION).tgz:
	wget -O $(@) $(OPENLDAP_DOWNLOAD)
	touch $(@)


$(TEST_TARGET)-downloaded: openldap-$(OPENLDAP_VERSION).tgz
	rm -Rf openldap
	rm -Rf openldap-$(OPENLDAP_VERSION)
	gzip -cd openldap-$(OPENLDAP_VERSION).tgz |tar -xf - \
	   || rm -Rf openldap-$(OPENLDAP_VERSION)
	mv openldap-$(OPENLDAP_VERSION) openldap
	touch $(@)


$(TEST_TARGET)-configure: $(TEST_TARGET)-downloaded
	rm -f $(@)
	cd openldap && ./configure \
	   --prefix=/tmp/openldap \
	   --enable-local \
	   --enable-slapd \
	   --enable-dynacl \
	   --enable-aci \
	   --enable-cleartext \
	   --enable-crypt \
	   --enable-syslog \
	   --enable-dynamic \
	   --enable-modules \
           --enable-accesslog=mod \
	   --enable-ppolicy=mod \
	   --enable-mdb=mod \
	   --enable-null=mod \
	   CFLAGS="-I/tmp/openldap/include -I/opt/local/include" \
	   CPPFLAGS="-I/tmp/openldap/include -I/opt/local/include" \
	   LDFLAGS="-L/tmp/openldap/lib -L/opt/local/lib" \
	   || rm -Rf ../openldap
	touch $(@)


$(TEST_TARGET)-depend: $(TEST_TARGET)-configure
	rm -f $(@)
	cd openldap && make -j $(NUMJOBS) depend
	touch $(@)


$(TEST_TARGET)-all: $(TEST_TARGET)-depend
	rm -f $(@)
	cd openldap && make -j $(NUMJOBS)
	touch $(@)


$(TEST_TARGET)-install: $(TEST_TARGET)-all
	rm -f $(@)
	cd openldap && make -j $(NUMJOBS) install
	mkdir /tmp/openldap/var/openldap-data
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/GNUmakefile: GNUmakefile $(TEST_TARGET)-all
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p GNUmakefile $(@)
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/pwdshadow.c: pwdshadow.c $(TEST_TARGET)-all
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p pwdshadow.c $(@)
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/pwdshadow.h: pwdshadow.h $(TEST_TARGET)-all
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p pwdshadow.h $(@)
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/docs/slapo-pwdshadow.5.in: docs/slapo-pwdshadow.5.in $(TEST_TARGET)-all
	mkdir -p openldap/contrib/slapd-modules/pwdshadow/docs
	cp -p docs/slapo-pwdshadow.5.in $(@)
	touch $(@)


docs/index.html: docs/slapo-pwdshadow.5
	rm -f $(@) $(@).new
	cat docs/slapo-pwdshadow.5 |groff -mandoc -Thtml > $(@).new
	grep -v '^<!-- Creat' $(@).new > $(@)
	rm -f $(@).new
	touch $(@)


html: docs/index.html


install: pwdshadow.la docs/slapo-pwdshadow.5
	mkdir -p $(DESTDIR)/$(moduledir)
	mkdir -p $(DESTDIR)$(man5dir)
	$(LIBTOOL) --mode=install $(INSTALL) -c pwdshadow.la $(DESTDIR)/$(moduledir)/pwdshadow.la
	$(INSTALL) -m 644 docs/slapo-pwdshadow.5 $(DESTDIR)$(man5dir)


uninstall:
	$(LIBTOOL) --mode=uninstall rm -f $(DESTDIR)/$(moduledir)/pwdshadow.la
	$(LIBTOOL) --mode=uninstall rm -f $(DESTDIR)$(man5dir)/slapo-pwdshadow.5


clean:
	rm -rf *.o *.lo *.la .libs docs/*.5
	rm -Rf openldap/contrib/slapd-modules/pwdshadow/*.o
	rm -Rf openldap/contrib/slapd-modules/pwdshadow/*.lo
	rm -Rf openldap/contrib/slapd-modules/pwdshadow/*.la
	rm -Rf openldap/contrib/slapd-modules/pwdshadow/.libs
	rm -Rf openldap/contrib/slapd-modules/pwdshadow/docs/*.5


distclean: clean
	rm -Rf openldap openldap-$(OPENLDAP_VERSION).tgz


# end of makefile
