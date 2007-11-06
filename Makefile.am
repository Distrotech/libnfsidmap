man_MANS = nfs4_uid_to_name.3
if ENABLE_LDAP
UMICH_LDAP_LIB = libnfsidmap_umich_ldap.la
else
UMICH_LDAP_LIB = 
endif
lib_LTLIBRARIES = libnfsidmap.la libnfsidmap_nsswitch.la $(UMICH_LDAP_LIB)
libnfsidmap_la_SOURCES = libnfsidmap.c cfg.c strlcpy.c cfg.h nfsidmap_internal.h queue.h
libnfsidmap_la_LDFLAGS = -version-info 2:0:2 -ldl
libnfsidmap_nsswitch_la_SOURCES = nss.c
libnfsidmap_nsswitch_la_LDFLAGS = -version-info 0:0:0
libnfsidmap_umich_ldap_la_SOURCES = umich_ldap.c
libnfsidmap_umich_ldap_la_LDFLAGS = -version-info 0:0:0 -lldap
include_HEADERS = nfsidmap.h
EXTRA_DIST = $(man_MANS) libtest.c idmapd.conf

#	XXX: also exclude debian/files and debian/files.new ? do a clean??
dist-hook:
	mkdir $(distdir)/debian/
	find $(srcdir)/debian -maxdepth 1 -not -type d |xargs -i cp {} $(distdir)/debian/

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA = libnfsidmap.pc

