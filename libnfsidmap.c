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
#include "nfsidmap_internal.h"
#include "cfg.h"

/* forward declarations */
int set_trans_method(int);

static char *default_domain;

static int method;

#ifndef PATH_IDMAPDCONF
#define PATH_IDMAPDCONF "/etc/idmapd.conf"
#endif

static char *conf_path = PATH_IDMAPDCONF;
static int initialized = 0;

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

static struct trans_func *trans;

int nfs4_init_name_mapping(char *conffile)
{
	int ret;

	/* XXX: need to be able to reload configurations... */
	if (initialized == 1)
		return 0;
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
	method = conf_get_num("Translation", "Method", TR_NSS);
	if (set_trans_method(method) == -1) {
		warnx("Error in translation table setup");
		return -1;
	}

	if (trans->init) {
		ret = trans->init();
		if (ret)
			return ret;
	}
	initialized = 1;

	return 0;
}

char * get_default_domain(void)
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

extern struct trans_func nss_trans;
extern struct trans_func umichldap_trans;

static struct trans_func * t_array[TR_SIZE + 1] = {
	[TR_NSS] = &nss_trans,
	[TR_UMICH_SCHEMA] = &umichldap_trans,
	[TR_SIZE] = NULL,
};

int
set_trans_method(int method)
{
	if (method > -1 && method < TR_SIZE) {
		trans = t_array[method];
		return 0;
	}
	return -1;
}

int nfs4_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	return trans->uid_to_name(uid, domain, name, len);
}

int nfs4_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	return trans->gid_to_name(gid, domain, name, len);
}

int nfs4_name_to_uid(char *name, uid_t *uid)
{
	return trans->name_to_uid(name, uid);
}

int nfs4_name_to_gid(char *name, gid_t *gid)
{
	return trans->name_to_gid(name, gid);
}

int nfs4_gss_princ_to_ids(char *princ, uid_t *uid, gid_t *gid)
{
	return trans->princ_to_ids(princ, uid, gid);
}
