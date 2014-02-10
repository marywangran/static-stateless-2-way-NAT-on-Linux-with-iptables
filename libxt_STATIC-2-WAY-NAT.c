/*
 *  根据Netfilter/iptables社区的友好相权，逼出来一个iptables接口。
 *  相比procfs要友好多了
 *
 *  起初，我就是嫌iptables模块写起来太麻烦，后来写过procfs接口之后才发现，
 *  原来最麻烦的不是例行公事的调用，而是字符串解析。使用iptables框架的好处
 *  在于它已经有了很多可重用的字符串解析以及到IP地址，端口的转换接口
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>

#include "xt_STATIC-2-WAY-NAT.h"

#undef XT_ALIGN
#define XT_ALIGN(s) (((s) + (__alignof__(struct _xt_align)-1))	\
					& ~(__alignof__(struct _xt_align)-1))

/* 枚举规则解析状态机的当前状态 */
enum {
	ADDR_OK	= (1<<0),
	TYPE_OK	= (1<<1),
	PROTO_OK = (1<<2),
	PORT_OK	= (1<<3),
	DEV_OK	= (1<<4),
};

/* 规则命令定义 */
static const struct option static_2_way_nat_tg_opts[] = {
	{.name = "mapaddr", .has_arg = true, .val = 'a'},
	{.name = "mapport", .has_arg = true, .val = 'o'},
	{.name = "proto", .has_arg = true, .val = 'p'},
	/* 本来想将type设置成source/destination的，但UNIX短名称传统更适合Linux */
	{.name = "type", .has_arg = true, .val = 't'},
	/* 本来想为dev设置inside/outside属性的，但是还是用Linux术语吧 */
	{.name = "dev", .has_arg = true, .val = 'd'},
	{},
};

static void static_2_way_nat_tg_help(void)
{
	printf(
"STATIC-2-WAY-NAT target options:\n"
"    --mapaddr from-to --type [src|dst] --dev [ethX] --proto [tcp|udp|all] --mapport from_port-to_port\n"
);
}

/* 从字符串解析IP地址 */
static void parse_addr(const char *orig_arg, struct xt_static_nat_tginfo *info)
{
	char *arg, *dash;
	size_t delta, len;
	u_int32_t from, to;
	arg = strdup(orig_arg);
	if (arg == NULL) {
		xtables_error(RESOURCE_PROBLEM, "strdup");
	}

	len = strlen(arg);
	dash = strchr(arg, '-');
	if (!dash) {
		xtables_error(RESOURCE_PROBLEM, "invalid argument.");
	}
	delta = dash - arg;
	arg[delta] = 0;
	from = inet_addr(arg);	
	if (from == INADDR_NONE){
		xtables_error(RESOURCE_PROBLEM, "invalid from address.");
	}
	info->addr[0] = from;

	arg += delta + 1;

	to = inet_addr(arg);	
	if (to == INADDR_NONE){
		xtables_error(RESOURCE_PROBLEM, "invalid to address.");
	}
	info->addr[1] = to;
}

/* 从字符串解析端口信息 */
static void parse_port(const char *orig_arg, struct xt_static_nat_tginfo *info)
{
	char *arg, *dash;
	size_t delta, len;
	u_int16_t from, to;
	arg = strdup(orig_arg);
	if (arg == NULL) {
		xtables_error(RESOURCE_PROBLEM, "strdup");
	}

	len = strlen(arg);
	dash = strchr(arg, '-');
	if (!dash) {
		xtables_error(RESOURCE_PROBLEM, "invalid argument.");
	}

	delta = dash - arg;
	arg[delta] = 0;
	from = atoi(arg);	
	if (from == 0){
		xtables_error(RESOURCE_PROBLEM, "invalid from port.");
	}
	info->port[0] = htons(from);

	arg += delta + 1;

	to = atoi(arg);	
	if (to == 0){
		xtables_error(RESOURCE_PROBLEM, "invalid to port.");
	}
	info->port[1] = htons(to);
}

/* iptables框架内的规则命令解析回调函数实现 */
static int
static_2_way_nat_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_target **target)
{
	int ret = false;
	struct xt_static_nat_tginfo *info = (void *)(*target)->data;

	switch (c) {
	case 'a':
		if (*flags & ADDR_OK) {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: multi addrmap.");
		} 
		parse_addr(optarg, info);

		/* 如果没有携带或者还没有解析到协议参数，则设置默认值 */
		if (!(*flags & PROTO_OK)) {
			info->proto = IPPROTO_MAX - 1;
		}

		/* 如果没有携带或者还没有解析到端口参数，则设置默认值 */
		if (!(*flags & PORT_OK)) {
			info->port[0] = 0;
			info->port[1] = 0;
		}

		/* 如果没有携带或者还没有解析到网卡参数，则设置默认值 */
		if (!(*flags & DEV_OK)) {
			memset(&info->dev[0], 0, MAX_DEV_NAME);
			strcpy(info->dev, "");
		}
		*flags |= ADDR_OK;
		ret = true;
		break;
	case 'o':
		if (*flags & PORT_OK) {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: multi portmap.");
		}
		parse_port(optarg, info);
		*flags |= PORT_OK;
		ret = true;
		break;
	case 'p':
		if (*flags & PROTO_OK) {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: multi protocol.");
		}
		if (!strcmp (optarg, "tcp")) {
			info->proto = IPPROTO_TCP;
		} else if (!strcmp (optarg, "udp")) {
			info->proto = IPPROTO_UDP;
		} else {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: invalid type.");
		}
		*flags |= PROTO_OK;
		ret = true;
		break;
	case 't':
		if (*flags & TYPE_OK) {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: multi type.");
		} 
		if (!strcmp (optarg, "src")) {
			info->dir = DIR_SNAT;
		} else if (!strcmp (optarg, "dst")) {
			info->dir = DIR_DNAT;
		} else {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: invalid type.");
		}
		*flags |= TYPE_OK;
		ret = true;
		break;
	case 'd':
		if (*flags & DEV_OK) {
			xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: multi device.");
		}
		strncpy(info->dev, optarg, MAX_DEV_NAME);
		*flags |= DEV_OK;
		ret = true;
		break;
	}
	return ret;
}

/* iptables框架内的规则命令解析完毕检查回调函数实现 */
static void static_2_way_nat_tg_check(unsigned int flags)
{
	/* 地址转换信息和类型[SNAT|DNAT]是必须要设置的 */
	if (!(flags & ADDR_OK) || !(flags & TYPE_OK)) {
		xtables_error(PARAMETER_PROBLEM, "STATIC-2-WAY-NAT: "
			"\"--mapaddr a.b.c.d-A.B.C.D and --type [src|dst]\" is required.");
	}
}

static void
static_2_way_nat_tg_print(const void *entry, const struct xt_entry_target *target,
                  int numeric)
{
	u_int32_t addr;
	const struct xt_static_nat_tginfo *info = (const void *)target->data;
	if (!info) {
		return;
	}
	addr = info->addr[0];
	printf(" --mapaddr %s-", xtables_ipaddr_to_numeric((struct in_addr *)&addr));
	addr = info->addr[1];
	printf("%s --type %s --proto %s --mapport %d-%d --dev %s",
				xtables_ipaddr_to_numeric((struct in_addr *)&addr),
				(info->dir == DIR_SNAT)?"src":"dst",
				(info->proto == IPPROTO_TCP)?"tcp":
											((info->proto == IPPROTO_UDP)?"udp":"all"),
				ntohs(info->port[0]),
				ntohs(info->port[1]),
				!strcmp(info->dev, "")?"all":info->dev);
}

/* iptables-save将按照该函数的实现来罗列规则 */
static void
static_2_way_nat_tg_save(const void *entry, const struct xt_entry_target *target)
{
	u_int32_t addr;
	const struct xt_static_nat_tginfo *info = (const void *)target->data;
	if (!info) {
		return;
	}
	addr = info->addr[0];
	printf(" --mapaddr %s-", xtables_ipaddr_to_numeric((struct in_addr *)&addr));
	addr = info->addr[1];
	printf("%s --type %s --proto %s --mapport %d-%d --dev %s",
				xtables_ipaddr_to_numeric((struct in_addr *)&addr),
				(info->dir == DIR_SNAT)?"src":"dst",
				(info->proto == IPPROTO_TCP)?"tcp":
											((info->proto == IPPROTO_UDP)?"udp":"all"),
				ntohs(info->port[0]),
				ntohs(info->port[1]),
				!strcmp(info->dev, "")?"all":info->dev);

}

static struct xtables_target static_2_way_nat_tg_reg = {
		.version       = XTABLES_VERSION,
		.name          = "STATIC-2-WAY-NAT",
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_static_nat_tginfo)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_static_nat_tginfo)),
		.help          = static_2_way_nat_tg_help,
		.parse         = static_2_way_nat_tg_parse,
		.final_check   = static_2_way_nat_tg_check,
		.print         = static_2_way_nat_tg_print,
		.save          = static_2_way_nat_tg_save,
		.extra_opts    = static_2_way_nat_tg_opts,
};

static __attribute__((constructor)) void static_2_way_nat_tg_ldr(void)
{
	xtables_register_target(&static_2_way_nat_tg_reg);
}
