/*
 *  nss.c
 *
 *  nsswitch idmapping functions.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
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
#include "nfsidmap_internal.h"
#include "cfg.h"

/*
 * NSS Translation Methods
 *
 * These are all just wrappers around getpwnam and friends;
 * we tack on the given domain to the results of getpwnam when looking up a uid,
 * and ignore the domain entirely when looking up a name.
 */

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

static int nss_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
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

static int nss_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
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
	l = malloc(len + 1);
	memcpy(l, name, len);
	l[len] = '\0';
	return l;
}

static int nss_name_to_uid(char *name, uid_t *uid)
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

static int nss_name_to_gid(char *name, gid_t *gid)
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

static int nss_gss_princ_to_ids(char *princ, uid_t *uid, uid_t *gid)
{
	char *localprinc;
	char *domain;
	struct passwd   *pw = NULL;

	domain = get_default_domain();
	localprinc = strip_domain(princ, domain);
	if (!localprinc)
		return -ENOMEM;
	if (!(pw = getpwnam(localprinc)) &&
		((memcmp("nfs/", localprinc, 4) != 0)
		 		|| !(pw = getpwnam("nobody"))))
		return -1;
	*uid = pw->pw_uid;
	*gid = pw->pw_gid;
	return 0;
}

struct trans_func nss_trans = {
	.method		= TR_NSS,
	.init		= NULL,
	.princ_to_ids	= nss_gss_princ_to_ids,
	.name_to_uid	= nss_name_to_uid,
	.name_to_gid	= nss_name_to_gid,
	.uid_to_name	= nss_uid_to_name,
	.gid_to_name	= nss_gid_to_name,
};
