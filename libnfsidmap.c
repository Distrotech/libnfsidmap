/*
 *  libnfsidmap.c
 *
 *  nfs idmapping library, primarily for nfs4 client/server kernel idmapping
 *  and for userland nfs4 idmapping by acl libraries.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <err.h>
#include "nfsidmap.h"
#include "cfg.h"

/* For now these are all just wrappers around getpwnam and friends;
 * we tack on the given domain to the results of getpwnam when looking up a uid,
 * and ignore the domain entirely when looking up a name.
 *
 * But the plan is to make more use of the domain in future.  E.g., consult
 * user-provided mapping from sets of domains to mapping mechanisms specified
 * possibly as follows:
 *
 * 	braindead.org: systemuid
 * 	*.citi.umich.edu,citi.umich.edu: system
 * 	*.umich.edu,umich.edu: ldap(some options here?)
 * 	*: nobody(nobody,nogroup)
 *
 * So braindead.org uses names that are of the form uid@braindead.org, whereas
 * citi machines just use getpwnam, other umich machines use ldap, and
 * everybody else uses a constant mapping.
 */

static char *default_domain;

#ifndef PATH_IDMAPDCONF
#define PATH_IDMAPDCONF "/etc/idmapd.conf"
#endif

static char *conf_path = PATH_IDMAPDCONF;

static int domain_from_dns(char **domain)
{
	struct hostent *he;
	char hname[64], *c;

	if (gethostname(hname, sizeof(hname)) == -1)
		return -1;
	if ((he = gethostbyname(hname)) == NULL)
		return -1;
	if ((c = strchr(he->h_name, '.')) == NULL || *++c == '\0')
		return -1;
	*domain = strdup(c);
	return 0;
}

int nfs4_init_name_mapping(char *conffile)
{
	int ret;

	if (conffile)
		conf_path = conffile;
	conf_init();
	default_domain = conf_get_str("General", "Domain");
	if (default_domain == NULL) {
		ret = domain_from_dns(&default_domain);
		if (ret) {
			warnx("unable to determine a default nfsv4 domain; "
				" consider specifying one in idmapd.conf\n");
			return ret;
		}
	}
	return 0;
}

static char * get_default_domain(void)
{
	int ret;

	if (default_domain)
		return default_domain;
	ret = domain_from_dns(&default_domain);
	if (ret) {
		warnx("unable to determine a default nfsv4 domain; "
			" consider specifying one in idmapd.conf\n");
		default_domain = "";
	}
	return default_domain;
}

static int write_name(char *dest, char *localname, char *domain, size_t len)
{
	if (strlen(localname) + 1 + strlen(domain) + 1 > len) {
		return -ENOMEM; /* XXX: Is there an -ETOOLONG? */
	}
	strcpy(dest, localname);
	strcat(dest, "@");
	strcat(dest, domain);
	return 0;
}

int nfs4_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	struct passwd *pw = NULL;
	struct passwd pwbuf;
	char *buf;
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	int err = -ENOMEM;

	buf = malloc(buflen);
	if (!buf)
		goto out;
	if (domain == NULL)
		domain = get_default_domain();
	err = -getpwuid_r(uid, &pwbuf, buf, buflen, &pw);
	if (pw == NULL)
		err = -ENOENT;
	if (err)
		goto out_buf;
	err = write_name(name, pw->pw_name, domain, len);
out_buf:
	free(buf);
out:
	return err;
}

int nfs4_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	struct group *gr = NULL;
	struct group grbuf;
	char *buf;
	size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	int err = -ENOMEM;

	buf = malloc(buflen);
	if (!buf)
		goto out;
	if (domain == NULL)
		domain = get_default_domain();
	err = -getgrgid_r(gid, &grbuf, buf, buflen, &gr);
	if (gr == NULL)
		err = -ENOENT;
	if (err)
		goto out_buf;
	err = write_name(name, gr->gr_name, domain, len);
out_buf:
	free(buf);
out:
	return err;
}

static char *strip_domain(char *name, char *domain)
{
	char *c, *l;
	int len;

	c = strchr(name, '@');
	if (!c)
		return NULL;
	if (strcmp(c + 1, domain) != 0)
		return NULL;
	len = c - name;
	l = malloc(index + 1);
	memcpy(l, name, len);
	l[len] = '\0';
	return l;
}

int nfs4_name_to_uid(char *name, uid_t *uid)
{
	struct passwd *pw = NULL;
	struct passwd pwbuf;
	char *buf, *localname, *domain;
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	int err = -ENOMEM;

	buf = malloc(buflen);
	if (!buf)
		goto out;
	domain = get_default_domain();
	localname = strip_domain(name, domain);
	if (!localname)
		goto out_buf;
	err = -getpwnam_r(localname, &pwbuf, buf, buflen, &pw);
	if (pw == NULL)
		err = -ENOENT;
	if (err)
		goto out_name;
	*uid = pw->pw_uid;
out_name:
	free(localname);
out_buf:
	free(buf);
out:
	return err;
}

int nfs4_name_to_gid(char *name, gid_t *gid)
{
	struct group *gr = NULL;
	struct group grbuf;
	char *buf, *localname, *domain;
	size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	int err = -ENOMEM;;

	buf = malloc(buflen);
	if (!buf)
		goto out;
	domain = get_default_domain();
	localname = strip_domain(name, domain);
	if (!localname)
		goto out_buf;
	err = -getgrnam_r(localname, &grbuf, buf, buflen, &gr);
	if (gr == NULL)
		err = -ENOENT;
	if (err)
		goto out_name;
	*gid = gr->gr_gid;
out_name:
	free(localname);
out_buf:
	free(buf);
out:
	return err;
}
