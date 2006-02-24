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

#include <sys/types.h>
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

#define UMICH_OBJCLASS_REMOTE_PERSON "NFSv4RemotePerson"
#define UMICH_OBJCLASS_REMOTE_GROUP  "NFSv4RemoteGroup"

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ        1024
#endif

/* Local structure definitions */

struct attribute_names {
	char *NFSv4_name_attr;
	char *NFSv4_group_attr;
	char *GSS_principal_attr;
};

struct attr {
	const char **u_attr[2];
};

struct umich_ldap_info {
	char *server;		/* server name/address */
	int  port;		/* server port */
	char *base;		/* base DN */
	char *people_tree;	/* DN to start searches for people */
	char *group_tree;	/* DN to start searches for groups */
};

/* GLOBAL data */

static struct umich_ldap_info ldap_info = {
	.server = NULL,
	.port = 0,
	.base = NULL,
	.people_tree = NULL,
	.group_tree = NULL,
};

static struct attribute_names attr_names = {
	.NFSv4_name_attr = NULL,
	.NFSv4_group_attr = NULL,
	.GSS_principal_attr = NULL,
};

/* Local routines */

static int
ldap_init_and_bind(LDAP **pld,
		     int *sizelimit,
		     struct umich_ldap_info *linfo)
{
	LDAP *ld;
#ifdef LDAP_BIND_REQUIRED
	int lerr;
#endif
	int err = -1;

	if (!(ld = ldap_init(linfo->server, linfo->port))) {
		IDMAP_LOG(2, ("ldap_init_and_bind: ldap_init failed "
			  "to [%s:%d]\n",
			  linfo->server, linfo->port));
		goto out;
	}

	if (sizelimit) {
		ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)sizelimit);
	}

#ifdef LDAP_BIND_REQUIRED
	lerr = ldap_simple_bind_s(ld, NULL, NULL);
	if (lerr) {
		IDMAP_LOG(2, ("ldap_init_and_bind: ldap_simple_bind_s "
			  "to [%s:%d]: %s (%d)\n", linfo->server, linfo->port,
			  ldap_err2string(lerr), lerr));
		goto out;
	}
#endif

	*pld = ld;
	err = 0;
  out:
	return err;
}

static int
name_to_nobody(uid_t *uid, gid_t *gid)
{
	struct passwd   *pw = NULL;

	if ( !(pw = getpwnam("nobody")) )
		return -1;
	*uid = pw->pw_uid;
	*gid = pw->pw_gid;
	return 0;
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
				     UMICH_OBJCLASS_REMOTE_PERSON,
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
				     UMICH_OBJCLASS_REMOTE_GROUP,
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

	attrs[0] = "uidNumber";
	attrs[1] = "gidNumber";
	attrs[2] = NULL;
	
	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err) {
		IDMAP_LOG(2, ("umich_name_to_ids: ldap_search_st for "
			  "base '%s, filter '%s': %s (%d)\n", base, filter,
			  ldap_err2string(err), err));
		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		goto out_unbind;
	}

	if (!(entry = ldap_first_entry(ld, result))){
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

		if (!(idstr = ldap_get_values(ld, result, attr_res))) {
			lerr = ldap_result2error(ld, result, 0);
			IDMAP_LOG(2, ("umich_name_to_ids: ldap_get_values: "
				  "%s (%d)\n", ldap_err2string(lerr), lerr));
			goto out_memfree;
		}
		if (strcasecmp(attr_res, "uidNumber") == 0) {
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
		} else if (strcasecmp(attr_res, "gidNumber") == 0) {
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
				     "(&(objectClass=%s)(uidNumber=%s))",
				     UMICH_OBJCLASS_REMOTE_PERSON, idstr))
			    	== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("ERROR: umich_id_to_name: "
				  "uid filter too long!\n"));
			goto out;
		}
		base = linfo->people_tree;
	} else if (idtype == IDTYPE_GROUP) {
		if ((f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				     "(&(objectClass=%s)(gidNumber=%s))",
				     UMICH_OBJCLASS_REMOTE_GROUP, idstr))
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

	attrs[0] = attr_names.NFSv4_name_attr;
	attrs[1] = NULL;

	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err) {
		IDMAP_LOG(2, ("umich_id_to_name: ldap_search_st for "
			  "base '%s, filter '%s': %s (%d)\n", base, filter,
			  ldap_err2string(err), err));
		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1)
		goto out_unbind;

	if (!(entry = ldap_first_entry(ld, result))){
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

	if (!(namestr = ldap_get_values(ld, result, attr_res))) {
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
			     UMICH_OBJCLASS_REMOTE_PERSON,
			     attr_names.GSS_principal_attr, principal))
		    	== LDAP_FILT_MAXSIZ) {
		IDMAP_LOG(0, ("ERROR: umich_gss_princ_to_grouplist: "
		      "filter too long!\n"));
		goto out;
	}

	attrs[0] = "uid";
	attrs[1] = NULL;

	err = ldap_search_st(ld, linfo->people_tree, LDAP_SCOPE_SUBTREE,
			 filter, attrs, 0, &timeout, &result);
	if (err) {
		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_search_st "
			  "for tree '%s, filter '%s': %s (%d)\n",
			  linfo->people_tree, filter,
			  ldap_err2string(err), err));
		err = -ENOENT;
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		goto out_unbind;
	}

	if (!(entry = ldap_first_entry(ld, result))){
		lerr = ldap_result2error(ld, result, 0);
		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_first_entry: "
			  "%s (%d)\n", ldap_err2string(lerr), lerr));
		goto out_unbind;
	}

	if (!(namestr = ldap_get_values(ld, result, attrs[0]))) {
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
			"(&(objectClass=posixGroup)(memberUid=%s))",
			*namestr)) == LDAP_FILT_MAXSIZ ) {
		IDMAP_LOG(0, ("ERROR: umich_gss_princ_to_grouplist: "
		      "filter too long!\n"));
		goto out_unbind;
	}

	attrs[0] = "gidNumber";
	attrs[1] = NULL;

	err = ldap_search_st(ld, linfo->group_tree, LDAP_SCOPE_SUBTREE,
			 filter, attrs, 0, &timeout, &result);
	if (err) {
		IDMAP_LOG(2, ("umich_gss_princ_to_grouplist: ldap_search_st "
			  "for tree '%s, filter '%s': %s (%d)\n",
			  linfo->group_tree, filter,
			  ldap_err2string(err), err));
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

		vals = ldap_get_values(ld, entry, "gidNumber");

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
			      "gidNumber too long converting '%s'\n", vals[0]));
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
			attr_names.GSS_principal_attr, &ldap_info);
	/*
	 * If no mapping in LDAP, but name starts with "nfs/",
	 * then map to nobody
	 */
	if ((err < 0) && (memcmp(principal, "nfs/", 4) == 0)){
		/* XXX: move this to svcgssd? */
		err = name_to_nobody(&rtnd_uid, &rtnd_gid);
	}
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
				 &gid, attr_names.NFSv4_name_attr, &ldap_info);
}

static int
umichldap_name_to_gid(char *name, gid_t *gid)
{
	uid_t uid;

	return umich_name_to_ids(name, IDTYPE_GROUP, &uid, gid,
				 attr_names.NFSv4_group_attr, &ldap_info);
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


static int
umichldap_init(void)
{
	char base[LDAP_FILT_MAXSIZ];
	int len;
	char *tp, *tg;

	ldap_info.server = conf_get_str("UMICH_SCHEMA", "LDAP_server");
	ldap_info.base = conf_get_str("UMICH_SCHEMA", "LDAP_base");
	ldap_info.port = conf_get_num("UMICH_SCHEMA", "LDAP_port", LDAP_PORT);
	tp = conf_get_str("UMICH_SCHEMA", "LDAP_people_subtree");
	tg = conf_get_str("UMICH_SCHEMA", "LDAP_group_subtree");

	attr_names.NFSv4_name_attr
		= conf_get_str("UMICH_SCHEMA", "NFSv4_name_attr");
	attr_names.NFSv4_group_attr
		= conf_get_str("UMICH_SCHEMA", "NFSv4_group_attr");
	attr_names.GSS_principal_attr
		= conf_get_str("UMICH_SCHEMA", "GSS_principal_attr");
	if (ldap_info.server == NULL
			|| ldap_info.base == NULL
			|| attr_names.NFSv4_name_attr == NULL
			|| attr_names.NFSv4_group_attr == NULL
			|| attr_names.GSS_principal_attr == NULL) {
		IDMAP_LOG(0,
			("umichldap_init: Error in translation table setup"));
		goto fail;
	}
	/*
	 * If people or group subtree was specified without
	 * specifying a value, just use the base value.
	 * If not specified at all, use the default.
	 * Otherwise, use what was specified.
	 */
	if (tp != NULL && strlen(tp) == 0) {
		if ((ldap_info.people_tree = strdup(ldap_info.base)) == NULL) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error duplicating base for people base"));
			goto fail;
		}
	} else {
		if ((len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
			(tp ? tp : "ou=People"), ldap_info.base))
						== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error forming people base"));
			goto fail;
		}
		if ((ldap_info.people_tree = strdup(base)) == NULL) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error duplicating people base"));
			goto fail;
		}
	}
	if (tg != NULL && strlen(tg) == 0) {
		if ((ldap_info.group_tree = strdup(ldap_info.base)) == NULL) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error duplicating base for group base"));
			goto fail;
		}
	} else {
		if ((len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
			(tg ? tg : "ou=Groups"), ldap_info.base))
						== LDAP_FILT_MAXSIZ) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error forming group base"));
			goto fail;
		}
		if ((ldap_info.group_tree = strdup(base)) == NULL) {
			IDMAP_LOG(0, ("umichldap_init: "
				  "Error duplicating group base"));
			goto fail;
		}
	}
	IDMAP_LOG(1, ("umichldap_init: server: %s\n", ldap_info.server));
	IDMAP_LOG(1, ("umichldap_init: port  : %d\n", ldap_info.port));
	IDMAP_LOG(1, ("umichldap_init: base  : %s\n", ldap_info.base));
	IDMAP_LOG(1, ("umichldap_init: people: %s\n", ldap_info.people_tree));
	IDMAP_LOG(1, ("umichldap_init: groups: %s\n", ldap_info.group_tree));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_name_attr   : %s\n",
		attr_names.NFSv4_name_attr));
	IDMAP_LOG(1, ("umichldap_init: NFSv4_group_attr  : %s\n",
		attr_names.NFSv4_group_attr));
	IDMAP_LOG(1, ("umichldap_init: GSS_principal_attr: %s\n",
		attr_names.GSS_principal_attr));
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
