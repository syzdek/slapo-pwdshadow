#
#   OpenLDAP pwdPolicy/shadowAccount Overlay
#   Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted only as authorized by the OpenLDAP
#   Public License.
#
#   A copy of this license is available in the file LICENSE in the
#   top-level directory of the distribution or, alternatively, at
#   <http://www.OpenLDAP.org/license.html>.
#

LTVERSION		= 0:0:0

OPENLDAP_VERSION	?= 2.5.14
OPENLDAP_DOWNLOAD	?= https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-$(OPENLDAP_VERSION).tgz


LIBTOOL			?= libtool
INSTALL			?= /usr/bin/install
CC			?= gcc
CFLAGS_EXTRA		+= -g -O2
CPPFLAGS_EXTRA		+= -I../../../include -I../../../servers/slapd -DSLAPD_OVER_PSHADOW=SLAPD_MOD_DYNAMIC
LDFLAGS_EXTRA		+=

prefix			?= /usr/local
exec_prefix		?= $(prefix)
libdir			?= $(exec_prefix)/lib
libexecdir		?= $(exec_prefix)/libexec
moduledir		?= $(libexecdir)/openldap
mandir			?= $(exec_prefix)/share/man
man5dir			?= $(mandir)/man5


.PHONY: all clean install test test-install test-env test-env-install


.SUFFIXES: .c .o .lo


all: pwdshadow.la


pwdshadow.lo: pwdshadow.c pwdshadow.h
	$(LIBTOOL) --tag=CC --mode=compile $(CC) $(CFLAGS) $(CFLAGS_EXTRA) \
	   $(CPPFLAGS) $(CPPFLAGS_EXTRA) -o pwdshadow.lo -c pwdshadow.c


pwdshadow.la: pwdshadow.lo
	$(LIBTOOL) --tag=CC --mode=link $(CC) $(LDFLAGS) $(LDFLAGS_EXTRA) \
	   -version-info $(LTVERSION) \
	   -rpath $(moduledir) -module -o pwdshadow.la pwdshadow.lo


test: test-env
	make -C openldap/contrib/slapd-modules/pwdshadow prefix=/tmp/openldap


test-install: test-env-install
	make -C openldap/contrib/slapd-modules/pwdshadow prefix=/tmp/openldap install


test-env-install: .test-env-install


test-env: .test-env


openldap-$(OPENLDAP_VERSION).tgz:
	wget -O $(@) $(OPENLDAP_DOWNLOAD)
	touch $(@)


openldap/.downloaded: openldap-$(OPENLDAP_VERSION).tgz
	rm -Rf openldap
	rm -Rf openldap-$(OPENLDAP_VERSION)
	gzip -cd openldap-$(OPENLDAP_VERSION).tgz |tar -xf - \
	   || rm -Rf openldap-$(OPENLDAP_VERSION)
	mv openldap-$(OPENLDAP_VERSION) openldap
	touch $(@)


openldap/Makefile: openldap/.downloaded
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
	   || rm -Rf openldap
	touch $(@)


openldap/.pwdshadow-depend: openldap/Makefile
	rm -f $(@)
	cd openldap && make -j 8 depend
	touch $(@)


openldap/.pwdshadow-all: openldap/.pwdshadow-depend
	rm -f $(@)
	cd openldap && make -j 8
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/GNUmakefile: GNUmakefile
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p GNUmakefile $(@)
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/pwdshadow.c: pwdshadow.c
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p pwdshadow.c $(@)
	touch $(@)


openldap/contrib/slapd-modules/pwdshadow/pwdshadow.h: pwdshadow.h
	mkdir -p openldap/contrib/slapd-modules/pwdshadow
	cp -p pwdshadow.h $(@)
	touch $(@)


.test-env: openldap/.pwdshadow-all
	rm -f $(@)
	rm -Rf openldap/contrib/slapd-modules/pwdshadow
	mkdir -p           openldap/contrib/slapd-modules/pwdshadow/doc
	ln     pwdshadow.c openldap/contrib/slapd-modules/pwdshadow/pwdshadow.c
	ln     pwdshadow.h openldap/contrib/slapd-modules/pwdshadow/pwdshadow.h
	ln     GNUmakefile openldap/contrib/slapd-modules/pwdshadow/GNUmakefile
	ln doc/slapo-pwdshadow.5 \
	   openldap/contrib/slapd-modules/pwdshadow/doc/slapo-pwdshadow.5
	touch              openldap/contrib/slapd-modules/pwdshadow/.test-env
	touch $(@)


.test-env-install: .test-env
	rm -f $(@)
	cd openldap && make -j 4 install
	mkdir -p /tmp/openldap/var/openldap-data
	cp doc/slapd.conf-test /tmp/openldap/etc/openldap/slapd.conf
	touch $(@)


install: pwdshadow.la
	mkdir -p $(DESTDIR)/$(moduledir)
	mkdir -p $(DESTDIR)$(man5dir)
	$(LIBTOOL) --mode=install $(INSTALL) -c pwdshadow.la $(DESTDIR)/$(moduledir)/pwdshadow.la
	$(INSTALL) -m 644 doc/slapo-pwdshadow.5 $(DESTDIR)$(man5dir)


uninstall:
	$(LIBTOOL) --mode=uninstall rm -f $(DESTDIR)/$(moduledir)/pwdshadow.la
	$(LIBTOOL) --mode=uninstall rm -f $(DESTDIR)$(man5dir)/slapo-pwdshadow.5


clean:
	rm -rf *.o *.lo *.la .libs
	rm -Rf openldap/contrib/slapd-modules/*.o
	rm -Rf openldap/contrib/slapd-modules/*.lo
	rm -Rf openldap/contrib/slapd-modules/*.la
	rm -Rf openldap/contrib/slapd-modules/.libs


distclean: clean
	rm -Rf .test-env .test-env-install openldap openldap-$(OPENLDAP_VERSION).tgz


# end of makefile
