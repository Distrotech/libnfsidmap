man_MANS = nfs4_uid_to_name.3
lib_LTLIBRARIES = libnfsidmap.la
libnfsidmap_la_SOURCES = libnfsidmap.c
include_HEADERS = nfsidmap.h
EXTRA_DIST = $(man_MANS)

dist-hook:
	mkdir $(distdir)/debian/
	find $(srcdir)/debian -maxdepth 1 -type f |xargs -i cp {} $(distdir)/debian/

