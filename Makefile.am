VERSION=0.10
man_MANS = nfs4_uid_to_name.3
lib_LTLIBRARIES = libnfsidmap.la
libnfsidmap_la_SOURCES = libnfsidmap.c nss.c umich_ldap.c cfg.c strlcpy.c cfg.h nfsidmap_internal.h queue.h
libnfsidmap_la_LDFLAGS = -version-info 1:0:1
include_HEADERS = nfsidmap.h
EXTRA_DIST = $(man_MANS)
LIBS = -lldap

dist-hook:
	mkdir $(distdir)/debian/
	find $(srcdir)/debian -maxdepth 1 -type f |xargs -i cp {} $(distdir)/debian/
	#XXX: also exclude debian/files and debian/files.new ? do a clean??
