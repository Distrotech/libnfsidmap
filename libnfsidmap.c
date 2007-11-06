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
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <err.h>
#include <syslog.h>
#include <stdarg.h>
#include <dlfcn.h>
#include "nfsidmap.h"
#include "nfsidmap_internal.h"
#include "cfg.h"

static char *default_domain;
static struct conf_list *local_realms;
int idmap_verbosity = 0;
static struct trans_func *trans = NULL;

#define PLUGIN_PREFIX "libnfsidmap_"
#define PLUGIN_INIT_FUNC "libnfsidmap_plugin_init"


#ifndef PATH_IDMAPDCONF
#define PATH_IDMAPDCONF "/etc/idmapd.conf"
#endif

/* Default logging fuction */
static void default_logger(const char *fmt, ...)
{
	va_list vp;

	va_start(vp, fmt);
	vsyslog(LOG_WARNING, fmt, vp); 
	va_end(vp);
}
nfs4_idmap_log_function_t idmap_log_func = default_logger;

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

static int load_translation_plugin(char *method) 
{
	void *dl;
	libnfsidmap_plugin_init_t init_func;
	char plgname[128];

	snprintf(plgname, sizeof(plgname), "%s%s.so", PLUGIN_PREFIX, method);

	dl = dlopen(plgname, RTLD_NOW | RTLD_LOCAL);
	if (dl == NULL) {
		IDMAP_LOG(1, ("libnfsidmap: Unable to load plugin: %s\n",
			  dlerror()));
		return -1;
	}
	init_func = (libnfsidmap_plugin_init_t) dlsym(dl, PLUGIN_INIT_FUNC);
	if (init_func == NULL) {
		IDMAP_LOG(1, ("libnfsidmap: Unable to get init function: %s\n",
			  dlerror()));
		dlclose(dl);
		return -1;
	}
	trans = init_func();
	if (trans == NULL) {
		IDMAP_LOG(1, ("libnfsidmap: Failed to initialize plugin %s\n", 
			  PLUGIN_INIT_FUNC, plgname));
		dlclose(dl);
		return -1;
	}

	return 0;
}

int nfs4_init_name_mapping(char *conffile)
{
	int ret;
	char *method;
	int dflt = 0;
	struct conf_list *realms;
	struct conf_list_node *node;

	/* XXX: need to be able to reload configurations... */
	if (trans) /* already succesfully initialized */
		return 0;
	if (conffile)
		conf_path = conffile;
	else
		conf_path = PATH_IDMAPDCONF;
	conf_init();
	default_domain = conf_get_str("General", "Domain");
	if (default_domain == NULL) {
		dflt = 1;
		ret = domain_from_dns(&default_domain);
		if (ret) {
			IDMAP_LOG(0, ("libnfsidmap: Unable to determine "
				  "a default nfsv4 domain; consider "
				  "specifying one in idmapd.conf\n"));
			return ret;
		}
	}
	IDMAP_LOG(1, ("libnfsidmap: using%s domain: %s\n",
		(dflt ? " (default)" : ""), default_domain));

	local_realms = conf_get_list("General", "Local-Realms");

	method = conf_get_str_with_def("Translation", "Method", "nsswitch");
	if (load_translation_plugin(method) == -1) {
		IDMAP_LOG(0, ("libnfsidmap: requested tranlation method, "
			 "'%s', is not available\n", method));
		return -1;
	}
	IDMAP_LOG(1, ("libnfsidmap: using translation method: %s\n", method)); 

	if (trans->init) {
		ret = trans->init();
		if (ret) {
			trans = NULL;
			return ret;
		}
	}

	return 0;
}

char * get_default_domain(void)
{
	int ret;

	if (default_domain)
		return default_domain;
	ret = domain_from_dns(&default_domain);
	if (ret) {
		IDMAP_LOG(0, ("Unable to determine a default nfsv4 domain; "
			" consider specifying one in idmapd.conf\n"));
		default_domain = "";
	}
	return default_domain;
}

struct conf_list *get_local_realms(void)
{
	return local_realms;
}

int
nfs4_get_default_domain(char *server, char *domain, size_t len)
{
	char *d = get_default_domain();

	if (strlen(d) + 1 > len)
		return -ERANGE;
	strcpy(domain, d);
	return 0;
}

int nfs4_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->uid_to_name(uid, domain, name, len);
}

int nfs4_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->gid_to_name(gid, domain, name, len);
}

int nfs4_name_to_uid(char *name, uid_t *uid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		goto out;
	ret = trans->name_to_uid(name, uid);
  out:
  	return ret;
}

int nfs4_name_to_gid(char *name, gid_t *gid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		goto out;
	ret = trans->name_to_gid(name, gid);
  out:
  	return ret;
}

int nfs4_gss_princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		goto out;
	ret = trans->princ_to_ids(secname, princ, uid, gid);
  out:
	return ret;
}

int nfs4_gss_princ_to_grouplist(char *secname, char *princ,
		gid_t *groups, int *ngroups)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		goto out;
	ret =  trans->gss_princ_to_grouplist(secname, princ, groups, ngroups);
  out:
  	return ret;
}

void nfs4_set_debug(int dbg_level, void (*logger)(const char *, ...))
{
	if (logger)
		idmap_log_func = logger;
	idmap_verbosity = dbg_level;	
}

