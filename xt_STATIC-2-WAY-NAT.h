#ifndef _LINUX_NETFILTER_XT_TARGET_STATICNAT
#define _LINUX_NETFILTER_XT_TARGET_STATICNAT 1

#define MAX_DEV_NAME	8

enum nat_dir {
	DIR_SNAT,
	DIR_DNAT,
	DIR_NUM = 2
};

struct xt_static_nat_tginfo {
	u_int32_t addr[DIR_NUM];
	u_int16_t port[DIR_NUM];
	u_int8_t proto;
	u_int8_t dir;
	char dev[MAX_DEV_NAME];
};

#endif /* _LINUX_NETFILTER_XT_TARGET_STATICNAT */
