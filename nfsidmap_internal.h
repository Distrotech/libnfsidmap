char *get_default_domain(void);

enum  trans_method_index{
	TR_NSS = 0,
	TR_UMICH_SCHEMA = 1,
	TR_SIZE	= 2,
};

struct trans_func {
	int method;
	int (*init)(void);
	int (*princ_to_ids)(char *princ, uid_t *uid, gid_t *gid);
	int (*name_to_uid)(char *name, uid_t *uid);
	int (*name_to_gid)(char *name, gid_t *gid);
	int (*uid_to_name)(uid_t uid, char *domain, char *name, size_t len);
	int (*gid_to_name)(gid_t gid, char *domain, char *name, size_t len);
};
