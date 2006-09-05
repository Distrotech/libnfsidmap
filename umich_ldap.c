/*
 * umich_ldap.c
 *
 * Copyright (c) 2000 The Regents of the University of Michigan.
 * All rights reserved.
 *
 * Copyright (c) 2004 Andy Adamson <andros@UMICH.EDU>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef ENABLE_LDAP

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <pwd.h>
#include <err.h>
#include <ldap.h>
#include "nfsidmap.h"
#include "nfsidmap_internal.h"
#include "cfg.h"

/* attribbute/objectclass default mappings */
#define DEFAULT_UMICH_OBJCLASS_REMOTE_PERSON	"NFSv4RemotePerson"
#define DEFAULT_UMICH_OBJCLASS_REMOTE_GROUP	"NFSv4RemoteGroup"
#define DEFAULT_UMICH_ATTR_NFSNAME		"NFSv4Name"
#define DEFAULT_UMICH_ATTR_ACCTNAME		"uid"
#define DEFAULT_UMICH_ATTR_UIDNUMBER		"uidNumber"
#define DEFAULT_UMICH_ATTR_GROUP_NFSNAME	"NFSv4Name"
#define DEFAULT_UMICH_ATTR_GIDNUMBER		"gidNumber"
#define DEFAULT_UMICH_ATTR_MEMBERUID		"memberUid"
#define DEFAULT_UMICH_ATTR_GSSAUTHNAME		"GSSAuthName"

/* config section */
#define LDAP_SECTION "UMICH_SCHEMA"

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ	1024
#endif

/* Local structure definitions */

struct ldap_map_names{
	char *NFSv4_person_objcls;
	char *NFSv4_nfsname_attr;
	char *NFSv4_acctname_attr;
	char *NFSv4_uid_attr;
	char *NFSv4_group_objcls;
	char *NFSv4_group_nfsname_attr;
	char *NFSv4_gid_attr;
	char *NFSv4_member_attr;
	char *GSS_principal_attr;
};

struct attr {
	const char **u_attr[2];
};

struct umich_ldap_info {
	char *server;		/* server name/address */
	int  port;		/* server port */
	char *base;		/* base DN */
	char *people_tree;	/* base DN to start searches for people */
	char *group_tree;	/* base DN to start searches for groups */
	char *user_dn;		/* optional DN for user account when binding */
	char *passwd;		/* Password to use when binding to directory */
	int use_ssl;		/* SSL flag */
	char *ca_cert;		/* File location of the ca_cert */
};

/* GLOBAL data */

static struct umich_ldap_info ldap_info = {
	.server = NULL,
	.port = 0,
	.base = NULL,
	.people_tree = NULL,
	.group_tree = NULL,
	.user_dn = NULL,
	.passwd = NULL,
	.use_ssl = 0,
	.ca_cert = NULL,
};

static struct ldap_map_names ldap_map = {
	.NFSv4_person_objcls = NULL,
	.NFSv4_nfsname_attr = NULL,
	.NFSv4_uid_attr = NULL,
	.NFSv4_acctname_attr = NULL,
	.NFSv4_group_objcls = NULL,
	.NFSv4_group_nfsname_attr = NULL,
	.NFSv4_gid_attr = NULL,
	.NFSv4_member_attr = NULL,
	.GSS_principal_attr = NULL,
};

/* Local routines */

static int
ldap_init_and_bind(LDAP **pld,
		   int *sizelimit,
		   struct umich_ldap_info *linfo)
{
	LDAP *ld;
	int lerr;
	int err = -1;
	int current_version, new_version;
	char server_url[1024];
	int debug_level = 65535;
	LDAPAPIInfo apiinfo = {.ldapai_info_version = LDAP_API_INFO_VERSION};

	snprintf(server_url, sizeof(server_url), "%s://%s:%d",
		 (linfo->use_ssl && linfo->ca_cert) ? "ldaps" : "ldap",
		 linfo->server, linfo->port);

	if ((lerr = ldap_initialize(&ld, server_url)) != LDAP_SUCCESS) {
		IDMAP_LOG(0, ("ldap_init_and_bind: ldap_initialize() failed "
			  "to [%s]: %s (%d)\n", server_url,
			  ldap_err2string(lerr), lerr));
		goto out;
	}

	if ((ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, &debug_level)
							!= LDAP_SUCCESS)) {
		IDMAP_LOG(0, ("ldap_init_and_bind: error setting ldap "
			  "library debugging level\n"));
		goto out;
	}

	/*
	 * Get LDAP API information and compare the protocol version there
	 * to the protocol version returned directly from get_option.
	 */
	ldap_get_option(ld, LDAP_OPT_API_INFO, &apiinfo);
	if (apiinfo.ldapai_info_version != LDAP_API_INFO_VERSION) {
		IDMAP_LOG(0, ("ldap_init_and_bind:  APIInfo version mismatch: "
			  "library %d, header %d\n",
			  apiinfo.ldapai_info_version, LDAP_API_INFO_VERSION));
		goto out;
	}
	ldap_get_option(ld, LDAP_OPT_PROTOCOL_VERSION, &current_version);
	if (apiinfo.ldapai_protocol_version == LDAP_VERSION3 &&
	    current_version != LDAP_VERSION3) {
		new_version = LDAP_VERSION3;
		IDMAP_LOG(4, ("ldap_init_and_bind: version mismatch between "
			  "API information and protocol version. Setting "
			  "protocol version to %d\n", new_version));
		ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &new_version);
	}

	/* Set sizelimit option if requested */
	if (sizelimit) {
		ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)sizelimit);
	}

	/* Set option to to use SSL/TLS if requested */
	if (linfo->use_ssl && linfo->ca_cert) {
		int tls_type = LDAP_OPT_X_TLS_HARD;

		lerr = ldap_set_option(ld, LDAP_OPT_X_TLS, &tls_type);
		if (lerr != LDAP_SUCCESS) {
			IDMAP_LOG(2, ("ldap_init_and_bind: setting SSL "
				  "failed : %s (%d)\n",
				  ldap_err2string(lerr), lerr));
			goto out;
		}
		lerr = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
				       linfo->ca_cert);
		if (lerr != LDAP_SUCCESS) {
			IDMAP_LOG(2, ("ldap_init_and_bind: setting CA "
				  "certificate file failed : %s (%d)\n",
				  ldap_err2string(lerr), lerr));
			goto out;
		}
	}

	/* If we have a DN (and password) attempt an authenticated bind */
	if (linfo->user_dn) {
retry_bind:
		lerr = ldap_simple_bind_s(ld, linfo->user_dn, linfo->passwd);
		if (lerr) {
			char *errmsg;
			if (lerr == LDAP_PROTOCOL_ERROR) {
				ldap_get_option(ld, LDAP_OPT_PROTOCOL_VERSION,
						&current_version); 
				new_version = current_version == LDAP_VERSION2 ?
					LDAP_VERSION3 : LDAP_VERSION2;
				ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
						&new_version); 
				IDMAP_LOG(2, ("ldap_init_and_bind: "
					  "got protocol error while attempting "
					  "bind with protocol version %d, "
					  "trying protocol version %d\n",
					  current_version, new_version));
				if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
					&& (errmsg != NULL) && (*errmsg != '\0')) {
					IDMAP_LOG(2, ("ldap_init_and_bind: "
						  "Additional info: %s\n", errmsg));
					ldap_memfree(errmsg);
				}
				goto retry_bind;
			}
			IDMAP_LOG(2, ("ldap_init_and_bind: ldap_simple_bind_s "
				  "to [%s] as user '%s': %s (%d)\n",
				  server_url, linfo->user_dn,
				  ldap_err2string(lerr), lerr));
			if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
					&& (errmsg != NULL)&& (*errmsg != '\0')) {
				IDMAP_LOG(2, ("ldap_init_and_bind: "
					  "Additional info: %s\n", errmsg));
				ldap_memfree(errmsg);
			}
			goto out;
		}
	}
#ifdef LDAP_ANONYMOUS_BIND_REQUIRED
	else {
		lerr = ldap_simple_bind_s(ld, NULL, NULL);
		if (lerr) {
			char *errmsg;

			IDMAP_LOG(2, ("ldap_init_and_bind: ldap_simple_bind_s "
			  "to [%s] as anonymous: %s (%d)\n", server_url,
			  ldap_err2string(lerr), lerr));
			if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
					&& (errmsg != NULL) && (*errmsg != '\0')) {
				IDMAP_LOG(2, ("ldap_init_and_bind: "
					  "Additional info: %s\n", errmsg));
				ldap_memfree(errmsg);
			}
			goto out;
		}
	}
#endif

	*pld = ld;
	err = 0;
out:
	return err;
}

static int
umich_name_to_ids(char *name, int idtype, uid_t *uid, gid_t *gid,
		  char *attrtype, struct umich_ldap_info *linfo)
{
	LDAP *ld = NULL;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	BerElement *ber = NULL;
	char **idstr, filter[LDAP_FILT_MAXSIZ], *base;
	char *attrs[3];
	char *attr_res;
	int count = 0, err, lerr, f_len;
	int sizelimit = 1;

	err = -EINVAL;
	if (uid == NULL || gid == NULL || name == NULL || 
	    attrtype == NULL || linfo == NULL || linfo->server == NULL ||
	    linfo->people_tree == NULL || linfo->group_tree == NULL)
		goto out;

	*uid = -1;
	*gid = -1;

	if (idtype == IDTYPE_USER) {
		if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				      "(&(objectClass=%s)(%s=%s))",
				      ldap_map.NFSv4_person_objcls,
				      attrtype, name))
				== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("ERROR: umich_name_to_ids: filter "
				  "too long!\n"));
			goto out;
		}
		base = linfo->people_tree;
	}
	else if (idtype == IDTYPE_GROUP) {
		if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				      "(&(objectClass=%s)(%s=%s))",
				      ldap_map.NFSv4_group_objcls,
				      attrtype, name))
				== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("ERROR: umich_name_to_ids: filter "
				  "too long!\n"));
			goto out;
		}
		base = linfo->group_tree;
	}
	else {
		IDMAP_LOG(0, ("ERROR: umich_name_to_ids: invalid idtype (%d)\n",
			idtype));
		goto out;
	}

	if (ldap_init_and_bind(&ld, &sizelimit, linfo))
		goto out;

	attrs[0] = ldap_map.NFSv4_uid_attr;
	attrs[1] = ldap_map.NFSv4_gid_attr;
	attrs[2] = NULL;
	
	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err) {
		char *errmsg;

		IDMAP_LOG(2, ("umich_name_to_ids: ldap_search_st for "
			  "base '%s', filter '%s': %s (%d)\n",
			  base, filter, ldap_err2string(err), err));
		if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
				&& (errmsg != NULL) && (*errmsg != '\0')) {
			IDMAP_LOG(2, ("umich_name_to_ids: "
				  "Additional info: %s\n", errmsg));
			ldap_memfree(errmsg);
		}
		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		goto out_unbind;
	}

	if (!(entry = ldap_first_entry(ld, result))) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_name_to_ids: ldap_first_entry: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	/*
	 * Attributes come back in no particular order, so we need
	 * to check each one to see what it is before assigning values.
	 * XXX There must be a better way than comparing the
	 * name of each attribute?
	 */
	for (attr_res = ldap_first_attribute(ld, result, &ber);
	     attr_res != NULL;
	     attr_res = ldap_next_attribute(ld, result, ber)) {

		unsigned long tmp_u, tmp_g;
		uid_t tmp_uid;
		gid_t tmp_gid;

		if ((idstr = ldap_get_values(ld, result, attr_res)) == NULL) {
			lerr = ldap_result2error(ld, result, 0);
			IDMAP_LOG(2, ("umich_name_to_ids: ldap_get_values: "
				  "%s (%d)\n", ldap_err2string(lerr), lerr));
			goto out_memfree;
		}
		if (strcasecmp(attr_res, ldap_map.NFSv4_uid_attr) == 0) {
			tmp_u = strtoul(*idstr, (char **)NULL, 10);
			tmp_uid = tmp_u;
			if (tmp_uid != tmp_u ||
				(errno == ERANGE && tmp_u == ULONG_MAX)) {
				IDMAP_LOG(0, ("ERROR: umich_name_to_ids: "
					  "uidNumber too long converting '%s'\n",
					  *idstr));
				ldap_memfree(attr_res);
				ldap_value_free(idstr);
				goto out_memfree;
			}
			*uid = tmp_uid;
		} else if (strcasecmp(attr_res, ldap_map.NFSv4_gid_attr) == 0) {
			tmp_g = strtoul(*idstr, (char **)NULL, 10);
			tmp_gid = tmp_g;
			if (tmp_gid != tmp_g ||
				(errno == ERANGE && tmp_g == ULONG_MAX)) {
				IDMAP_LOG(0, ("ERROR: umich_name_to_ids: "
					  "gidNumber too long converting '%s'\n",
					  *idstr));
				ldap_memfree(attr_res);
				ldap_value_free(idstr);
				goto out_memfree;
			}
			*gid = tmp_gid;
		} else {
			IDMAP_LOG(0, ("umich_name_to_ids: received attr "
				"'%s' ???\n", attr_res));
			ldap_memfree(attr_res);
			ldap_value_free(idstr);
			goto out_memfree;
		}
		ldap_memfree(attr_res);
		ldap_value_free(idstr);
	}

	err = 0;
out_memfree:
	ber_free(ber, 0);
out_unbind:
	ldap_unbind(ld);
out:
	return err;
}

static int
umich_id_to_name(uid_t id, int idtype, char **name, size_t len,
		 struct umich_ldap_info *linfo)
{
	LDAP *ld = NULL;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	BerElement *ber;
	char **namestr, filter[LDAP_FILT_MAXSIZ], *base;
	char idstr[16];
	char *attrs[2];
	char *attr_res;
	int count = 0, err, lerr, f_len;
	int sizelimit = 1;

	err = -EINVAL;
	if (name == NULL || linfo == NULL || linfo->server == NULL || 
		linfo->people_tree == NULL || linfo->group_tree == NULL)
		goto out;

	snprintf(idstr, sizeof(idstr), "%d", id);


	if (idtype == IDTYPE_USER) {
		if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				      "(&(objectClass=%s)(%s=%s))",
				      ldap_map.NFSv4_person_objcls,
				      ldap_map.NFSv4_uid_attr, idstr))
				== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("ERROR: umich_id_to_name: "
				  "uid filter too long!\n"));
			goto out;
		}
		base = linfo->people_tree;
	} else if (idtype == IDTYPE_GROUP) {
		if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				      "(&(objectClass=%s)(%s=%s))",
				      ldap_map.NFSv4_group_objcls, 
				      ldap_map.NFSv4_gid_attr,idstr))
				== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("ERROR: umich_id_to_name: "
				  "gid filter too long!\n"));
			goto out;
		}
		base = linfo->group_tree;
	} else {
		IDMAP_LOG(0, ("ERROR: umich_id_to_name: invalid idtype (%d)\n",
			  idtype));
		err = -EINVAL;
		goto out;
	}

	if (ldap_init_and_bind(&ld, &sizelimit, linfo))
		goto out;

	attrs[0] = ldap_map.NFSv4_nfsname_attr;
	attrs[1] = NULL;

	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err) {
		char * errmsg;

		IDMAP_LOG(2, ("umich_id_to_name: ldap_search_st for "
			  "base '%s, filter '%s': %s (%d)\n", base, filter,
			  ldap_err2string(err), err));
                if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
				&& (errmsg != NULL) && (*errmsg != '\0')) {
			IDMAP_LOG(2, ("umich_id_to_name: "
				  "Additional info: %s\n", errmsg));
			ldap_memfree(errmsg);
		}

		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1)
		goto out_unbind;

	if (!(entry = ldap_first_entry(ld, result))) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_id_to_name: ldap_first_entry: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	if (!(attr_res = ldap_first_attribute(ld, result, &ber))) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_id_to_name: ldap_first_attribute: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	if ((namestr = ldap_get_values(ld, result, attr_res)) == NULL) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_id_to_name: ldap_get_values: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_memfree;
	}

	memcpy (*name, *namestr, strlen(*namestr));

	err = 0;
out_memfree:
	ldap_memfree(attr_res);
	ber_free(ber, 0);
out_unbind:
	ldap_unbind(ld);
out:
	return err;
}

static int
umich_gss_princ_to_grouplist(char *principal, gid_t *groups, int *ngroups,
			     struct umich_ldap_info *linfo)
{
	LDAP *ld = NULL;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	char **namestr, filter[LDAP_FILT_MAXSIZ];
	char *attrs[2];
	int count = 0, err = -ENOMEM, lerr, f_len;
	gid_t *curr_group;

	err = -EINVAL;
	if (linfo == NULL || linfo->server == NULL ||
		linfo->people_tree == NULL || linfo->group_tree == NULL)
		goto out;


	if (ldap_init_and_bind(&ld, NULL, linfo))
		goto out;

	/*
	 * First we need to map the gss principal name to a uid (name) string
	 */
	err = -EINVAL;
	if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
			     "(&(objectClass=%s)(%s=%s))",
			     ldap_map.NFSv4_person_objcls,
			     ldap_map.GSS_principal_attr, principal))
			== LDAP_FILT_MAXSIZ) {
		IDMAP_LOG(0, ("ERROR: umich_gss_princ_to_grouplist: "
			  "filter too long!\n"));
		goto out;
	}

	attrs[0] = ldap_map.NFSv4_acctname_attr;
	attrs[1] = NULL;

	err = ldap_search_st(ld, linfo->people_tree, LDAP_SCOPE_SUBTREE,
			 filter, attrs, 0, &timeout, &result);
	if (err) {
		char *errmsg;

		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_search_st "
			  "for tree '%s, filter '%s': %s (%d)\n",
			  linfo->people_tree, filter,
			  ldap_err2string(err), err));
		if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS)
				&& (errmsg != NULL) && (*errmsg != '\0')) {
			IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: "
				   "Additional info: %s\n", errmsg));
			ldap_memfree(errmsg);
		}
		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		goto out_unbind;
	}

	if (!(entry = ldap_first_entry(ld, result))) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_first_entry: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	if ((namestr = ldap_get_values(ld, result, attrs[0])) == NULL) {
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_get_values: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	/*
	 * Then determine the groups that uid (name) string is a member of
	 */
	err = -EINVAL;
	if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
			"(&(objectClass=%s)(%s=%s))",
			ldap_map.NFSv4_group_objcls,
			ldap_map.NFSv4_member_attr,
			*namestr)) == LDAP_FILT_MAXSIZ ) {
		IDMAP_LOG(0, ("ERROR: umich_gss_princ_to_grouplist: "
			  "filter too long!\n"));
		goto out_unbind;
	}

	attrs[0] = ldap_map.NFSv4_gid_attr;
	attrs[1] = NULL;

	err = ldap_search_st(ld, linfo->group_tree, LDAP_SCOPE_SUBTREE,
			 filter, attrs, 0, &timeout, &result);
	if (err) {
		char *errmsg;

		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_search_st "
			  "for tree '%s, filter '%s': %s (%d)\n",
			  linfo->group_tree, filter,
			  ldap_err2string(err), err));
		if ((ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errmsg) == LDAP_SUCCESS) &&
				(errmsg != NULL) && (*errmsg != '\0')) {
			IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: "
				   "Additional info: %s\n", errmsg));
			ldap_memfree(errmsg);
		}
		err = -ENOENT;
		goto out_unbind;
	}

	/*
	 * If we can't determine count, return that error
	 * If we have nothing to return, return success
	 * If we have more than they asked for, tell them the
	 * number required and return an error
	 */
	count = ldap_count_entries(ld, result);
	if (count < 0) {
		err = count;
		goto out_unbind;
	}
	if (count == 0) {
		*ngroups = 0;
		err = 0;
		goto out_unbind;
	}
	if (count > *ngroups) {
		*ngroups = count;
		err = -EINVAL;
		goto out_unbind;
	}
	*ngroups = count;

	curr_group = groups;

	err = -ENOENT;
	for (entry = ldap_first_entry(ld, result);
	     entry != NULL;
	     entry = ldap_next_entry(ld, entry)) {

		char **vals;
		int valcount;
		unsigned long tmp_g;
		gid_t tmp_gid;

		vals = ldap_get_values(ld, entry, ldap_map.NFSv4_gid_attr);

		/* There should be only one gidNumber attribute per group */
		if ((valcount = ldap_count_values(vals)) != 1) {
			IDMAP_LOG(0, ("DB problem getting gidNumber of "
				  "posixGroup! (count was %d)\n", valcount));
			goto out_unbind;
		}
		tmp_g = strtoul(vals[0], (char **)NULL, 10);
		tmp_gid = tmp_g;
		if (tmp_gid != tmp_g ||
				(errno == ERANGE && tmp_g == ULONG_MAX)) {
			IDMAP_LOG(0, ("ERROR: umich_gss_princ_to_grouplist: "
				  "gidNumber too long converting '%s'\n",
				  vals[0]));
			ldap_value_free(vals);
			goto out_unbind;
		}
		*curr_group++ = tmp_gid;
		ldap_value_free(vals);
	}
	err = 0;
out_unbind:
	ldap_unbind(ld);
out:
	return err;
}


/*
 * principal:   krb5  - princ@realm, use KrbName ldap attribute
 *              spkm3 - X.509 dn, use X509Name ldap attribute
 */
static int
umichldap_gss_princ_to_ids(char *secname, char *principal,
			   uid_t *uid, gid_t *gid)
{
	uid_t rtnd_uid = -1;
	gid_t rtnd_gid = -1;
	int err = -EINVAL;

	if ((strcmp(secname, "krb5") != 0) && (strcmp(secname, "spkm3") != 0)) {
		IDMAP_LOG(0, ("ERROR: umichldap_gss_princ_to_ids: "
			  "invalid secname '%s'\n", secname));
		return err;
	}

	err = umich_name_to_ids(principal, IDTYPE_USER, &rtnd_uid, &rtnd_gid,
			ldap_map.GSS_principal_attr, &ldap_info);
	if (err < 0)
		goto out;

	*uid = rtnd_uid;
	*gid = rtnd_gid;
out:
	return err;
}

static int
umichldap_name_to_uid(char *name, uid_t *uid)
{
	gid_t gid;

	return umich_name_to_ids(name, IDTYPE_USER, uid,
				 &gid, ldap_map.NFSv4_nfsname_attr, &ldap_info);
}

static int
umichldap_name_to_gid(char *name, gid_t *gid)
{
	uid_t uid;

	return umich_name_to_ids(name, IDTYPE_GROUP, &uid, gid,
				 ldap_map.NFSv4_group_nfsname_attr, &ldap_info);
}

static int
umichldap_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	return umich_id_to_name(uid, IDTYPE_USER, &name, len, &ldap_info);
}

static int
umichldap_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	return umich_id_to_name(gid, IDTYPE_GROUP, &name, len, &ldap_info);
}

static int
umichldap_gss_princ_to_grouplist(char *secname, char *principal,
		gid_t *groups, int *ngroups)
{
	int err = -EINVAL;

	if ((strcmp(secname, "krb5") != 0) && (strcmp(secname, "spkm3") != 0)) {
		IDMAP_LOG(0, ("ERROR: umichldap_gss_princ_to_grouplist: "
			  "invalid secname '%s'\n", secname));
		return err;
	}

	return umich_gss_princ_to_grouplist(principal, groups, ngroups,
					    &ldap_info);
}

/*
 * TLS connections require that the hostname we specify matches
 * the hostname in the certificate that the server uses.
 * Get a canonical name for the host specified in the config file.
 */
static char *
get_canonical_hostname(const char *inname)
{
	int aierr, error;
	struct addrinfo *ap, aihints;
	char *return_name = NULL;
	char tmphost[NI_MAXHOST];

	memset(&aihints, 0, sizeof(aihints));
	aihints.ai_socktype = SOCK_STREAM;
	aihints.ai_flags = AI_CANONNAME;
	aihints.ai_family = PF_INET;
	aierr = getaddrinfo(inname, NULL, &aihints, &ap);
	if (aierr) {
		const char *msg;
		/* We want to customize some messages.  */
		switch (aierr) {
		case EAI_NONAME:
			msg = "host unknown";
			break;
		default:
			msg = gai_strerror(aierr);
			break;
		}
		IDMAP_LOG(1, ("%s: '%s': %s\n", __FUNCTION__, inname, msg));
		goto out_err;
	}
	if (ap == 0) {
		IDMAP_LOG(1, ("%s: no addresses for host '%s'?\n",
			  __FUNCTION__, inname));
		goto out_err;
	}

	error = getnameinfo (ap->ai_addr, ap->ai_addrlen, tmphost,
			     sizeof(tmphost), NULL, 0, 0);
	if (error) {
		IDMAP_LOG(1, ("%s: getnameinfo for host '%s' failed (%d)\n",
			  __FUNCTION__, inname));
		goto out_err;
	}
	return_name = strdup (tmphost);

out_free:
	freeaddrinfo(ap);
out_err:
	return return_name;
}

static int
umichldap_init(void)
{
	char *tssl, *canonicalize;
	int missing_server = 0, missing_base = 0;
	char missing_msg[128] = "";
	char *server_in, *canon_name;

	server_in = conf_get_str(LDAP_SECTION, "LDAP_server");
	ldap_info.base = conf_get_str(LDAP_SECTION, "LDAP_base");
	ldap_info.people_tree = conf_get_str(LDAP_SECTION, "LDAP_people_base");
	ldap_info.group_tree = conf_get_str(LDAP_SECTION, "LDAP_group_base");
	ldap_info.user_dn = conf_get_str(LDAP_SECTION, "LDAP_user_dn");
	ldap_info.passwd = conf_get_str(LDAP_SECTION, "LDAP_passwd");
	tssl = conf_get_str_with_def(LDAP_SECTION, "LDAP_use_ssl", "false");
	if ((strcasecmp(tssl, "true") == 0) ||
	    (strcasecmp(tssl, "on") == 0) ||
	    (strcasecmp(tssl, "yes") == 0))
		ldap_info.use_ssl = 1;
	else
		ldap_info.use_ssl = 0;
	ldap_info.ca_cert = conf_get_str(LDAP_SECTION, "LDAP_CA_CERT");
	/* vary the default port depending on whether they use SSL or not */
	ldap_info.port = conf_get_num(LDAP_SECTION, "LDAP_port",
				      (ldap_info.use_ssl) ?
				      LDAPS_PORT : LDAP_PORT);

	/* Verify required information is supplied */
	if (server_in == NULL || strlen(server_in) == 0)
		strncat(missing_msg, "LDAP_server ", sizeof(missing_msg));
	if (ldap_info.base == NULL || strlen(ldap_info.base) == 0)
		strncat(missing_msg, "LDAP_base ", sizeof(missing_msg));
	if (strlen(missing_msg) != 0) {
		IDMAP_LOG(0, ("umichldap_init: Missing required information: "
			  "%s\n", missing_msg));
		goto fail;
	}
  
	ldap_info.server = server_in;
	canonicalize = conf_get_str_with_def(LDAP_SECTION, "LDAP_canonicalize_name", "yes");
	if ((strcasecmp(canonicalize, "true") == 0) ||
	    (strcasecmp(canonicalize, "on") == 0) ||
	    (strcasecmp(canonicalize, "yes") == 0)) {
		canon_name = get_canonical_hostname(server_in);
		if (canon_name == NULL)
			IDMAP_LOG(0, ("umichldap_init: Warning! Unable to "
				  "canonicalize server name '%s' as requested.\n",
				  server_in));
		else
			ldap_info.server = canon_name;
	}

	/* get the ldap mapping attributes/objectclasses (all have defaults) */
	ldap_map.NFSv4_person_objcls =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_person_objectclass",
				      DEFAULT_UMICH_OBJCLASS_REMOTE_PERSON);
	
	ldap_map.NFSv4_group_objcls =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_group_objectclass",
				      DEFAULT_UMICH_OBJCLASS_REMOTE_GROUP);
	
	ldap_map.NFSv4_nfsname_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_name_attr",
				      DEFAULT_UMICH_ATTR_NFSNAME);
	
	ldap_map.NFSv4_uid_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_uid_attr",
				      DEFAULT_UMICH_ATTR_UIDNUMBER);
	
	ldap_map.NFSv4_acctname_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_acctname_attr",
				      DEFAULT_UMICH_ATTR_ACCTNAME);
	
	ldap_map.NFSv4_group_nfsname_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_group_attr",
				      DEFAULT_UMICH_ATTR_GROUP_NFSNAME);
	
	ldap_map.NFSv4_gid_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_gid_attr",
				      DEFAULT_UMICH_ATTR_GIDNUMBER);

	ldap_map.NFSv4_member_attr =
		conf_get_str_with_def(LDAP_SECTION, "NFSv4_member_attr",
				      DEFAULT_UMICH_ATTR_MEMBERUID);

	ldap_map.GSS_principal_attr =
		conf_get_str_with_def(LDAP_SECTION, "GSS_principal_attr",
				      DEFAULT_UMICH_ATTR_GSSAUTHNAME);
	
	/*
	 * If they specified a search base for the
	 * people tree or group tree we use that.
	 * Otherwise we use the default search base.
	 * Note:  We no longer append the default base to the tree --
	 * that should already be specified.
	 * this functions much like the NSS_LDAP modules
	 */

	if (ldap_info.people_tree == NULL || strlen(ldap_info.people_tree) == 0)
		ldap_info.people_tree = ldap_info.base;
	if (ldap_info.group_tree == NULL || strlen(ldap_info.group_tree) == 0)
		ldap_info.group_tree = ldap_info.base;

	if (ldap_info.use_ssl && ldap_info.ca_cert == NULL) {
		IDMAP_LOG(0, ("umichldap_init: You must specify LDAP_ca_cert "
			  "with LDAP_use_ssl=yes\n"));
		goto fail;
	}


	/* print out some good debugging info */
	IDMAP_LOG(1, ("umichldap_init: canonicalize_name: %s\n",
		  canonicalize));
	IDMAP_LOG(1, ("umichldap_init: server  : %s (from config value '%s')\n",
		  ldap_info.server, server_in));
	IDMAP_LOG(1, ("umichldap_init: port    : %d\n", ldap_info.port));
	IDMAP_LOG(1, ("umichldap_init: people  : %s\n", ldap_info.people_tree));
	IDMAP_LOG(1, ("umichldap_init: groups  : %s\n", ldap_info.group_tree));

	IDMAP_LOG(1, ("umichldap_init: user_dn : %s\n",
		  (ldap_info.user_dn && strlen(ldap_info.user_dn) != 0)
		  ? ldap_info.user_dn : "<not-supplied>"));
	/* Don't print actual password into the log. */
	IDMAP_LOG(1, ("umichldap_init: passwd  : %s\n",
		  (ldap_info.passwd && strlen(ldap_info.passwd) != 0) ?
		  "<supplied>" : "<not-supplied>"));
	IDMAP_LOG(1, ("umichldap_init: use_ssl : %s\n",
		  ldap_info.use_ssl ? "yes" : "no"));
	IDMAP_LOG(1, ("umichldap_init: ca_cert : %s\n",
		  ldap_info.ca_cert ? ldap_info.ca_cert : "<not-supplied>"));

	IDMAP_LOG(1, ("umichldap_init: NFSv4_person_objectclass : %s\n",
		  ldap_map.NFSv4_person_objcls));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_nfsname_attr       : %s\n",
		  ldap_map.NFSv4_nfsname_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_acctname_attr      : %s\n",
		  ldap_map.NFSv4_acctname_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_uid_attr           : %s\n",
		  ldap_map.NFSv4_uid_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_group_objectclass  : %s\n",
		  ldap_map.NFSv4_group_objcls));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_gid_attr           : %s\n",
		  ldap_map.NFSv4_gid_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_group_nfsname_attr : %s\n",
		  ldap_map.NFSv4_group_nfsname_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_member_attr        : %s\n",
		  ldap_map.NFSv4_member_attr));
	IDMAP_LOG(1, ("umichldap_init: GSS_principal_attr       : %s\n",
		  ldap_map.GSS_principal_attr));
	return 0;
fail:
  	return -1;
}


/* The external interface */

struct trans_func umichldap_trans = {
	.name		= "umich_ldap",
	.init		= umichldap_init,
	.princ_to_ids   = umichldap_gss_princ_to_ids,
	.name_to_uid    = umichldap_name_to_uid,
	.name_to_gid    = umichldap_name_to_gid,
	.uid_to_name    = umichldap_uid_to_name,
	.gid_to_name    = umichldap_gid_to_name,
	.gss_princ_to_grouplist = umichldap_gss_princ_to_grouplist,
};

#endif
