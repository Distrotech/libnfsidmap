if ENABLE_LDAP
UMICH_LDAP_LIB = libnfsidmap_umich_ldap.la
else
UMICH_LDAP_LIB = 
endif
if ENABLE_GUMS
GUMS_MAPPING_LIB = libnfsidmap_gums.la
else
GUMS_MAPPING_LIB =
endif
lib_LTLIBRARIES = libnfsidmap.la libnfsidmap_nsswitch.la libnfsidmap_static.la \
		  $(UMICH_LDAP_LIB) $(GUMS_MAPPING_LIB)

# Library versioning notes from:
#  http://sources.redhat.com/autobook/autobook/autobook_91.html
#
# -version-info <current>:<revision>:<age>
#  <current>	The number of the current interface exported by library.
#  <revision>	The implementation number of the most recent interface
#		exported by the library.  (i.e. revision should be updated
#		with each new release of the library, and reset to zero
#		when <current> is updated.)
#  <age> 	The number of previous additional interfaces supported
#  		by this library.

libnfsidmap_la_SOURCES = libnfsidmap.c cfg.c strlcpy.c cfg.h nfsidmap_internal.h queue.h
libnfsidmap_la_LDFLAGS = -version-info 3:0:3 -ldl

libnfsidmap_nsswitch_la_SOURCES = nss.c
libnfsidmap_nsswitch_la_LDFLAGS = -version-info 0:0:0

libnfsidmap_static_la_SOURCES = static.c
libnfsidmap_static_la_LDFLAGS = -version-info 0:0:0

libnfsidmap_umich_ldap_la_SOURCES = umich_ldap.c
libnfsidmap_umich_ldap_la_LDFLAGS = -version-info 0:0:0 -lldap

libnfsidmap_gums_la_SOURCES = gums.c
libnfsidmap_gums_la_LDFLAGS = -version-info 0:0:0

man3_MANS = nfs4_uid_to_name.3
man5_MANS	= idmapd.conf.5
include_HEADERS = nfsidmap.h

EXTRA_DIST = $(man3_MANS) \
	     $(man5_MANS) \
	     libtest.c \
	     idmapd.conf

#	XXX: also exclude debian/files and debian/files.new ? do a clean??
dist-hook:
	mkdir $(distdir)/debian/
	find $(srcdir)/debian -maxdepth 1 -not -type d |xargs -i cp {} $(distdir)/debian/

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA = libnfsidmap.pc

