/*
 *  libtest.c
 *
 *  nfs idmapping library, primarily for nfs4 client/server kernel idmapping
 *  and for userland nfs4 idmapping by acl libraries.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
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
 *
 *
 *
 *  libtest: Test the translation table functions
 *           Reads /etc/idmapd.conf
 *
 *  To compile:
 *  gcc -g libtest.c -lnfsidmap -o libtest
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <nfsidmap.h>

#define PATH_IDMAPDCONF "/etc/idmapd.conf"
char *conf_path = PATH_IDMAPDCONF;

main(int ac, char **av)
{
	char *name, *princ;
	int err, uid = 0, gid = 0;
	char name_buf[32];

	if (ac != 3) {
		printf("Usage: %s <user@nfsv4domain> <k5princ@REALM>\n",av[0]);
		return;
	}

	name = av[1];
	princ = av[2];
	err = nfs4_init_name_mapping(NULL);

	err = nfs4_gss_princ_to_ids(princ, &uid, &gid);
	printf("nfs4_gss_princ_to_ids: princ %s has uid %d gid %d\n",
	         princ, uid, gid);

	err = nfs4_name_to_uid(name, &uid);
	printf("nfs4_name_to_uid: name %s has uid %d\n",
	         name, uid);

	err = nfs4_name_to_gid(name, &gid);
	printf("nfs4_name_to_uid: name %s has gid %d\n",
	         name, gid);

	/* uid is set by nfs4_name_to_uid() */
	memset(name_buf, 0, 32);
	err = nfs4_uid_to_name(uid, NULL, name_buf, 32);
	printf("nfs4_uid_to_name: uid %d has name %s\n",
	         uid, name_buf);

	/* gid is set by nfs4_name_to_gid() */
	memset(name_buf, 0, 32);
	err = nfs4_gid_to_name(gid, NULL, name_buf, 32);
	printf("nfs4_gid_to_name: gid %d has name %s\n",
	         gid, name_buf);
}
