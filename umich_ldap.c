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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <ldap.h>
#include <string.h>
#include <err.h>
#include "cfg.h"
#include "nfsidmap_internal.h"

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

/* GLOBAL data */

char *ldap_server = NULL, *ldap_base = NULL;
static struct attribute_names attr_names = {
	.NFSv4_name_attr = NULL,
};

/* Local routines */

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
		  char *attrtype, char *lserver, char *lbase)
{
	int m_id;
	LDAP *ld = NULL;
	int port = LDAP_PORT;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	BerElement *ber = NULL;
	char **idstr, filter[LDAP_FILT_MAXSIZ], base[LDAP_FILT_MAXSIZ];
	struct attr uid_attr;
	char *attrs[3];
	char *attr_res;
	int count = 0,  err, f_len, b_len;
	int sizelimit = 1;

	err = -EINVAL;
	if (uid == NULL || gid == NULL || name == NULL || 
	    attrtype == NULL || lserver == NULL || lbase == NULL)
		goto out;

	*uid = -1;
	*gid = -1;

	if (idtype == IDTYPE_USER) {
		if (f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				     "(&(objectClass=%s)(%s=%s))",
				     UMICH_OBJCLASS_REMOTE_PERSON,
				     attrtype, name)
				== LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_name_to_ids: filter too long!\n");
			goto out;
		}
		if (b_len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
				"ou=People", lbase) == LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_name_to_ids: base too long!\n");
			goto out;
		}
	}
	else if (idtype == IDTYPE_GROUP) {
		if (f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				     "(&(objectClass=%s)(%s=%s))",
				     UMICH_OBJCLASS_REMOTE_GROUP,
				     attrtype, name)
				== LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_name_to_ids: filter too long!\n");
			goto out;
		}
		if (b_len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
				"ou=Groups", lbase) == LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_name_to_ids: base too long!\n");
			goto out;
		}
	}
	else {
		warnx("ERROR: umich_name_to_ids: invalid idtype (%d)\n",
			idtype);
		goto out;
	}

	if (!(ld = ldap_init(lserver, port))) {
		warnx("ldap_init failed to [%s:%d]\n", lserver, port);
		goto out;
	}

	ldap_set_option(ld, LDAP_OPT_SIZELIMIT,(void *)&sizelimit);
	m_id = ldap_simple_bind(ld, NULL, NULL);
	if (m_id < 0) {
		ldap_perror(ld,"ldap_simple_bind");
		goto out;
	}

	err = ldap_result(ld, m_id, 0, &timeout, &result);
	if (err < 0 ) {
		warnx("ERROR: ldap_result of simple bind\n");
		goto out;
	}

	attrs[0] = "uidNumber";
	attrs[1] = "gidNumber";
	attrs[2] = NULL;
	
	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err < 0 ) {
		ldap_perror(ld, "ldap_search_st");
		warnx("ldap_result2err of search error: %d\n",err);
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		goto out_unbind;
	}

	if (!(entry = ldap_first_entry(ld, result))){
		ldap_perror(ld, "ldap_first_entry\n");
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
		if (!(idstr = ldap_get_values(ld, result, attr_res))) {
			ldap_perror(ld, "ldap_get_values\n");
			goto out_memfree;
		}
		if (strcasecmp(attr_res, "uidNumber") == 0) {
			*uid = atoi(*idstr);
		} else if (strcasecmp(attr_res, "gidNumber") == 0) {
			*gid = atoi(*idstr);
		} else {
			warnx("umich_name_to_ids: received attr '%s' ???\n",
				attr_res);
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
		 char *lserver, char *lbase)
{
	int m_id;
	LDAP *ld = NULL;
	int port = LDAP_PORT;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	BerElement *ber;
	char **namestr, filter[LDAP_FILT_MAXSIZ], base[LDAP_FILT_MAXSIZ];
	char idstr[16];
	struct attr name_attr;
	char *attrs[2];
	char *attr_res;
	int count = 0,  err, f_len, b_len;
	int sizelimit = 1;

	err = -EINVAL;
	if (lserver == NULL || lbase == NULL || name == NULL)
		goto out;

	snprintf(idstr, sizeof(idstr), "%d", id);


	if (idtype == IDTYPE_USER) {
		if (f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				     "(&(objectClass=%s)(uidNumber=%s))",
				     UMICH_OBJCLASS_REMOTE_PERSON, idstr)
			    	== LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_id_to_name: filter too long!\n");
			goto out;
		}
		if (b_len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
				"ou=People", lbase) == LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_id_to_name: base too long!\n");
			goto out;
		}

	} else if (idtype == IDTYPE_GROUP) {
		if (f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
				     "(&(objectClass=%s)(gidNumber=%s))",
				     UMICH_OBJCLASS_REMOTE_GROUP, idstr)
			    	== LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_id_to_name: filter too long!\n");
			goto out;
		}
		if (b_len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
				"ou=Groups", lbase) == LDAP_FILT_MAXSIZ) {
			warnx("ERROR: umich_id_to_name: base too long!\n");
			goto out;
		}

	} else {
		warnx("ERROR: umich_id_to_name: invalid idtype (%d)\n", idtype);
		err = -EINVAL;
		goto out;
	}

	if (!(ld = ldap_init(lserver, port))) {
		warnx("ldap_init failed to [%s:%d]\n", lserver, port);
		goto out;
	}

	ldap_set_option(ld, LDAP_OPT_SIZELIMIT,(void *)&sizelimit);
	m_id = ldap_simple_bind(ld, NULL, NULL);
	if (m_id < 0) {
		ldap_perror(ld,"ldap_simple_bind");
		goto out;
	}

	err = ldap_result(ld, m_id, 0, &timeout, &result);
	if (err < 0 ) {
		warnx("ERROR: ldap_result of simple bind\n");
		goto out;
	}

	attrs[0] = attr_names.NFSv4_name_attr;
	attrs[1] = NULL;

	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, (char **)attrs,
			 0, &timeout, &result);
	if (err < 0 ) {
		ldap_perror(ld, "ldap_search_st");
		goto out_unbind;
	}

	err = -ENOENT;
	count = ldap_count_entries(ld, result);
	if (count != 1)
		goto out_unbind;

	if (!(entry = ldap_first_entry(ld, result))){
		printf("ldap_first_entry error: entry %p\n",entry);
		ldap_perror(ld, "ldap_first_entry\n");
		goto out_unbind;
	}

	if (!(attr_res = ldap_first_attribute(ld, result, &ber))) {
		printf("ldap_first_attribute returns %p\n", attr_res);
		ldap_perror(ld, "ldap_first_attribute\n");
		goto out_unbind;
	}

	if (!(namestr = ldap_get_values(ld, result, attr_res))) {
		ldap_perror(ld, "ldap_first_attribute\n");
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
umich_uid_to_grouplist(uid_t uid, gid_t *groups, int *ngroups,
		       char *lserver, char *lbase)
{
	int m_id;
	LDAP *ld = NULL;
	int port = LDAP_PORT;
	struct timeval timeout = {
		.tv_sec = 2,
	};
	LDAPMessage *result, *entry;
	char **namestr, filter[LDAP_FILT_MAXSIZ], base[LDAP_FILT_MAXSIZ];
	char uidstr[16];
	struct attr name_attr;
	char *attrs[2];
	int count = 0,  err = -ENOMEM, f_len, b_len;
	gid_t *curr_group;

	err = -EINVAL;
	if (lserver == NULL || lbase == NULL)
		goto out;

	snprintf(uidstr, sizeof(uidstr), "%d", uid);

	if (f_len = snprintf(filter, LDAP_FILT_MAXSIZ,
			"(&(objectClass=posixGroup)(memberUid=%s))",
			uidstr) == LDAP_FILT_MAXSIZ ) {
		warnx("ERROR: umich_uid_to_grouplist: filter too long!\n");
		goto out;
	}

	if (b_len = snprintf(base, LDAP_FILT_MAXSIZ, "%s,%s",
			"ou=Groups", lbase) == LDAP_FILT_MAXSIZ) {
		warnx("ERROR: umich_uid_to_grouplist: base too long!\n");
		goto out;
	}


	if (!(ld = ldap_init(lserver, port))) {
		warnx("ldap_init failed to [%s:%d]\n", lserver, port);
		goto out;
	}

	m_id = ldap_simple_bind(ld, NULL, NULL);
	if (m_id < 0) {
		ldap_perror(ld,"ldap_simple_bind");
		goto out;
	}

	err = ldap_result(ld, m_id, 0, &timeout, &result);
	if (err < 0 ) {
		warnx("ERROR: ldap_result of simple bind\n");
		goto out;
	}

	attrs[0] = "gidNumber";
	attrs[1] = NULL;

	err = ldap_search_st(ld, base, LDAP_SCOPE_SUBTREE,
			 filter, attrs,
			 0, &timeout, &result);
	if (err < 0 ) {
		ldap_perror(ld, "ldap_search_st");
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

	curr_group = groups;

	err = -ENOENT;
	for (entry = ldap_first_entry(ld, result);
	     entry != NULL;
	     entry = ldap_next_entry(ld, entry)) {

		char **vals;
		int valcount;

		vals = ldap_get_values(ld, entry, "gidNumber");

		/* There should be only one gidNumber attribute per group */
		if ((valcount = ldap_count_values(vals)) != 1) {
			warnx("DB problem getting gidNumber of "
			      "posixGroup! (count was %d)\n", valcount);
			goto out_unbind;
		}
		*curr_group++ = atoi(vals[0]);
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

	if (strcmp(secname, "krb5") != 0) {
		warnx("ERROR: umichldap_gss_princ_to_ids: invalid secname '%s'\n", secname);
		return err;
	}

	err = umich_name_to_ids(principal, IDTYPE_USER, &rtnd_uid, &rtnd_gid,
			attr_names.GSS_principal_attr, ldap_server,ldap_base);
	/*
	 * If no mapping in LDAP, but name starts with "nfs/*",
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

	return umich_name_to_ids(name, IDTYPE_USER, uid, &gid, attr_names.NFSv4_name_attr,
					ldap_server, ldap_base);
}

static int
umichldap_name_to_gid(char *name, gid_t *gid)
{
	uid_t uid;

	return umich_name_to_ids(name, IDTYPE_GROUP, &uid, gid, attr_names.NFSv4_group_attr,
					ldap_server, ldap_base);
}

static int
umichldap_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	return umich_id_to_name(uid, IDTYPE_USER, &name, len,
					ldap_server, ldap_base);
}

static int
umichldap_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	return umich_id_to_name(gid, IDTYPE_GROUP, &name, len,
					ldap_server, ldap_base);
}

static int
umichldap_gss_princ_to_grouplist(char *secname, char *principal,
		gid_t *groups, int *ngroups)
{
	uid_t rtnd_uid = -1;
	gid_t rtnd_gid = -1;
	int err = -EINVAL;

	/* XXX Is this check necessary??? */
	if (strcmp(secname, "krb5") != 0) {
		warnx("ERROR: umichldap_gss_princ_to_grouplist: "
		      "invalid secname '%s'\n", secname);
		return err;
	}

	/* First we need to find a UID for the principal name */
	err = umich_name_to_ids(principal, IDTYPE_USER, &rtnd_uid, &rtnd_gid,
			attr_names.GSS_principal_attr, ldap_server, ldap_base);

	/* If we can't map principal name to UID, we can't continue... */
	if (err < 0) {
		*ngroups = 0;
		return 0;
	}
	return umich_uid_to_grouplist(rtnd_uid, groups, ngroups,
					ldap_server, ldap_base);
}


static int
umichldap_init(void)
{
	ldap_server = conf_get_str("UMICH_SCHEMA", "LDAP_server");
	ldap_base = conf_get_str("UMICH_SCHEMA", "LDAP_base");
	attr_names.NFSv4_name_attr
		= conf_get_str("UMICH_SCHEMA", "NFSv4_name_attr");
	attr_names.NFSv4_group_attr
		= conf_get_str("UMICH_SCHEMA", "NFSv4_group_attr");
	attr_names.GSS_principal_attr
		= conf_get_str("UMICH_SCHEMA", "GSS_principal_attr");
	if (ldap_server == NULL
			|| ldap_base == NULL
			|| attr_names.NFSv4_name_attr == NULL
			|| attr_names.NFSv4_group_attr == NULL
			|| attr_names.GSS_principal_attr == NULL) {
		warnx("Error in translation table setup");
		return -1;
	}
	return 0;
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
