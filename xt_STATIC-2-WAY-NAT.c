/* 
 *
 * procfs接口的用法(已经禁用)：
 * 对目标地址为1.2.1.2的数据包做目标地址转换，目标转为192.168.1.8
 * echo +1.2.1.2 192.168.1.8 dst >/proc/net/static_nat
 * 上述命令会同时添加一条反向的SNAT映射
 *
 * 上述命令添加协议支持：
 * echo +1.2.1.2 192.168.1.8 dst tcp >/proc/net/static_nat
 *
 * 继续增加端口映射的支持：
 * echo +1.2.1.2 192.168.1.8 dst tcp port-map 1234 80 >/proc/net/static_nat
 *
 * 请解释：
 * echo +192.168.184.250 192.168.184.154 src >/proc/net/static_nat
 *
 * iptables接口的用法：
 * 见下面的详细注释。
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ctype.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>

#include <linux/netfilter/x_tables.h>
#include "xt_STATIC-2-WAY-NAT.h"

static __be16 skip_atos(const char *s)
{
	__be16 i = 0;
	while (isdigit(*s)) {
		i = i * 10 + *((s)++) - '0';
	}
	return i;
}

#define DIRMASK	0x11
#define BUCKETS	1024

#define ENTRY_ADD	0x10
#define ENTRY_DEL	0x20

#define NAT_OPT_DEL			0x01
#define NAT_OPT_FIND		0x04

#define NAT_OPT_ACCT_BIT	0x02

/*
 * 记录统计信息
 */
struct nat_account {
	u32 nat_packets;
	u32 nat_bytes;
};

/*
 * 这个entry数据结构的设计有两个选择：
 * 1.复杂模式：
 *		即将所有的信息都展现于entry本身，skb匹配过程根据skb本身的IP地址信息作为key，
 *		找到entry后再匹配第四层协议。
 * 2.简单模式：
 *		即设置多张保存简单entry(仅仅保存IP地址映射信息)的hlist，每个协议一张表，匹配
 *		时仅仅需要匹配从skb中取出的protocol相关的hlist即可。
 * 很明显，第二种效率更高，但是也更松散，本实现采用第一种，日后补充实现第二种。
 */
struct static_nat_entry {
	__be32 addr[DIR_NUM];
	/* 该entry适用的第四层协议 */
	u_int8_t proto;
	union {
		__be16 all[DIR_NUM];
		struct {
			__be16 port[DIR_NUM];
		} tcp;
		struct {
			__be16 port[DIR_NUM];
		} udp;
		/* ...... */
	} u;

	enum nat_dir type;
	struct net_device *dev;
	struct nat_account acct[DIR_NUM];
	struct hlist_node node[DIR_NUM];
};

/*
 * 返回查询结果
 */
struct map_result {
	__be32 addr;
	__be16 port;
};

static DEFINE_SPINLOCK(nat_lock);

/* 保存SNAT映射 */
struct hlist_head *src_list;

/* 保存DNAT映射 */
struct hlist_head *dst_list;

/*
 * 用一个IP地址(对于PREROUTING是daddr，对于POSTROUTING是saddr)作为key来获取value。
 */
static unsigned int get_address_from_map(unsigned int dir, 
											__be32 addr_key, 
											__be16 port_key, 
											u8 proto_key, 
											unsigned int opt, 
											struct map_result *res,
											unsigned int datalen,
											const struct net_device *dev)
{
	unsigned int ret = -1;
	/* 首先匹配明细协议，然后再匹配通配协议 */
	int try = 1;
	__be32 cmp_key, ret_addr;
	u32 hash;
	struct hlist_head *list;
	struct hlist_node *iter, *tmp;
	struct static_nat_entry *ent;

	/* 将协议作为hash计算的一部分，可以让来自同一地址的连接散列效果更好，
	 * 但是代价就是如果匹配不成功，则需要将协议设置为缺省通配协议，重新
	 * 匹配一次。
	 *
	 * 我的第一个版本在计算hash时并没有指定proto字段，第二个版本指定了，
	 * 因为经过我模拟的压力测试表明，对于配置明细协议的规则而言，匹配
	 * 会更加迅速。也就是说，这个效率和iptables是一样的，和你配置的规则
	 * 有关，即：最好配置带有明细协议的规则，而不是配置通配规则(你考虑
	 * 的少了，机器就要多考虑，反过来想让机器不考虑那么多，你自己就要
	 * 多考虑！)
	 */
try_agin:

	hash = jhash_2words(addr_key, (__be32)proto_key, 1);
	hash = hash%BUCKETS;

	spin_lock(&nat_lock);
	if (dir == DIR_DNAT) {
		list = &dst_list[hash];
	} else if (dir == DIR_SNAT) {
		list = &src_list[hash];
	} else {
		spin_unlock(&nat_lock);
		goto out;
	}

	hlist_for_each_safe(iter, tmp, list) {
		ent = hlist_entry(iter, struct static_nat_entry, node[dir]);
		/* 注意反转 */
		cmp_key = (ent->type == dir) ?
							ent->addr[0]:ent->addr[1];
		ret_addr = (ent->type == dir) ?
							ent->addr[1]:ent->addr[0];
		if (addr_key == cmp_key) {
			__be16 cmp_port = (ent->type == dir) ?
								ent->u.all[0]:ent->u.all[1];
			__be16 ret_port = (ent->type == dir) ?
								ent->u.all[1]:ent->u.all[0];

			if (ent->proto != IPPROTO_MAX - 1 && ent->proto != proto_key) {
				continue;
			}

			/* 如果addr比较不通过，就无需下面的了 */
			if (cmp_port) {

				/* 如果port不参与比较，就无需下面的了 */
				if (cmp_port != port_key) {
					continue;
				}
			}

			if (dev && ent->dev && dev != ent->dev) {
				continue;
			}

			/* 实际上，上面的嵌套if完全可以用C的布尔逻辑搞定，但是那样的话if条件会很长 */
			ret = 0;
			res->addr = ret_addr;
			res->port = ret_port;
			try = try - 1;
			if (opt == NAT_OPT_DEL) {
				if (dir == ent->type) {
					hlist_del(&ent->node[0]);
					hlist_del(&ent->node[1]);
					if (ent->dev) {
						dev_put(ent->dev);
					}
					kfree(ent);
				} else {
					ret = -1;
				}
			}
			if (opt & NAT_OPT_ACCT_BIT) {
				ent->acct[dir].nat_packets ++;
				ent->acct[dir].nat_bytes += datalen;
			}
			break;
		} 
	}
	spin_unlock(&nat_lock);
	if (try > 0) {
		try = try - 1;
		proto_key = IPPROTO_MAX - 1;
		goto try_agin;
	}
out:
	return ret;
}

/*
 * 处理第七层的函数
 * 它处理第七层协议中携带地址端口信息的情况。
 * 作为一个简单的例子，我用一个自定义的协议来举例：
 * ...||layer3||layer4||saddr|daddr||
 */
static int process_l7(struct sk_buff *skb, unsigned int dir, __be32 newaddr, __be16 newport)
{
	int ret = 0;
	goto out;
out:
	return ret;
}

static u8 get_l4_proto(struct sk_buff *skb)
{
	u8 ret = IPPROTO_MAX - 1;
	struct iphdr *iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		ret = IPPROTO_TCP;
		break;
	case IPPROTO_UDP:
		ret = IPPROTO_UDP;
		break;
	default:
		ret= IPPROTO_MAX - 1;
		break;
	}
	return ret;
}

static s16 get_l4_port(struct sk_buff *skb, unsigned int dir)
{
	struct iphdr *iph = ip_hdr(skb);
	void *transport_hdr = (void *)iph + ip_hdrlen(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	__be16 ret = 0;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = transport_hdr;
		if (dir == DIR_SNAT) {
			ret = tcph->source;	
		} else if(dir == DIR_DNAT) {
			ret = tcph->dest;
		} else {
			ret = 0;
		}
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = transport_hdr;
		if (dir == DIR_SNAT) {
			ret = udph->source;	
		} else if(dir == DIR_DNAT) {
			ret = udph->dest;
		} else {
			ret = 0;
		}
		break;
	default:
		ret = 0;
	}
	return ret;
}

static void set_l4_port(struct sk_buff *skb, unsigned int dir, __be16 port)
{
	struct iphdr *iph = ip_hdr(skb);
	void *transport_hdr = (void *)iph + ip_hdrlen(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = transport_hdr;
		if (dir == DIR_SNAT) {
			tcph->source = port;	
		} else if(dir == DIR_DNAT) {
			tcph->dest = port;
		}
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = transport_hdr;
		if (dir == DIR_SNAT) {
			udph->source = port;	
		} else if(dir == DIR_DNAT) {
			udph->dest = port;
		} 
		break;
	}
}

/*
 * 更新第四层的校验码信息
 */
static void nat4_update_l4(struct sk_buff *skb, 
							__be32 oldip, __be32 newip, 
							__be16 oldport, __be16 newport)
{
	struct iphdr *iph = ip_hdr(skb);
	void *transport_hdr = (void *)iph + ip_hdrlen(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	bool cond;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = transport_hdr;
		inet_proto_csum_replace4(&tcph->check, skb, oldip, newip, 1);
		if (newport) {
			inet_proto_csum_replace2(&tcph->check, skb, oldport, newport, 0);
		}
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = transport_hdr;
		cond = udph->check != 0;
		cond |= skb->ip_summed == CHECKSUM_PARTIAL;
		if (cond) {
			inet_proto_csum_replace4(&udph->check, skb, oldip, newip, 1);
			if (newport) {
				inet_proto_csum_replace2(&udph->check, skb, oldport, newport, 0);
			}
			if (udph->check == 0) {
				udph->check = CSUM_MANGLED_0;
			}
		}
		break;
	}
}

/*
 * 在POSTROUTING上执行源地址转换：
 * 1.正向源地址转换；
 * 2.目标地址转换的逆向源地址转换
 */
static unsigned int ipv4_nat_out(unsigned int hooknum,
				 struct sk_buff *skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 int (*okfn)(struct sk_buff *))
{
	unsigned int ret = NF_ACCEPT, res = 0;
	struct map_result mres;
	struct iphdr *hdr = ip_hdr(skb);
	__be16 port = 0;
	u8 proto;
	
	port = get_l4_port(skb, DIR_SNAT);
	proto = get_l4_proto(skb);

	memset(&mres, 0, sizeof(mres));
	res = get_address_from_map(DIR_SNAT, hdr->saddr, port, proto, NAT_OPT_FIND|NAT_OPT_ACCT_BIT, &mres, skb->len, out);
	if (res) {
		goto out;
	}

	if (hdr->saddr == mres.addr) {
		goto out;
	}

	/* 执行SNAT */	
	if (process_l7(skb, DIR_DNAT, mres.addr, mres.port)) {
		/* 如果第七层发生了改变，则重新计算相关校验码 */
	}
	csum_replace4(&hdr->check, hdr->saddr, mres.addr);
	nat4_update_l4(skb, hdr->saddr, mres.addr, port, mres.port);
	if (mres.port) {
		set_l4_port(skb, DIR_SNAT, mres.port);
	}
	hdr->saddr = mres.addr;
out:
 	return ret;
}

/*
 * 在PREROUTING上执行目标地址转换：
 * 1.正向目标地址转换；
 * 2.源地址转换的逆向目标地址转换
 */
static unsigned int ipv4_nat_in(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
	unsigned int ret = NF_ACCEPT, res = 0;
	struct map_result mres;
	struct iphdr *hdr = ip_hdr(skb);
	__be16 port = 0;
	u8 proto;
	
	port = get_l4_port(skb, DIR_DNAT);
	proto = get_l4_proto(skb);

	if (skb->nfct && skb->nfct != &nf_conntrack_untracked.ct_general) {
		goto out;
	}
	
	memset(&mres, 0, sizeof(mres));
	res = get_address_from_map(DIR_DNAT, hdr->daddr, port, proto, NAT_OPT_FIND|NAT_OPT_ACCT_BIT, &mres, skb->len, in);
	if (res) {
		goto out;
	}

	if (hdr->daddr == mres.addr) {
		goto out;
	}
	
	/* 执行DNAT */
	if (process_l7(skb, DIR_DNAT, mres.addr, mres.port)) {
		/* 如果第七层发生了改变，则重新计算相关校验码 */
	}
	csum_replace4(&hdr->check, hdr->daddr, mres.addr);
	nat4_update_l4(skb, hdr->daddr, mres.addr, port, mres.port);
	if (mres.port) {
		set_l4_port(skb, DIR_DNAT, mres.port);
	}
	hdr->daddr = mres.addr;
	
	/*
	 *  设置一个notrack 防止其被track以及nat.
	 *  这是绝对合适的，因为既然是static的stateless NAT
	 *  我们就不希望它被状态左右
	 **/

	/*
	 * 其实，并不是主要避开基于conntrack的NAT就可以了，因为
	 * conntrack本身就不容你对两个方向的tuple进行随意修改
	 */
	if (!skb->nfct) {
		skb->nfct = &nf_conntrack_untracked.ct_general;
		skb->nfctinfo = IP_CT_NEW;
		nf_conntrack_get(skb->nfct);
	}

out:
	return ret;
}

static struct nf_hook_ops ipv4_nat_ops[] __read_mostly = {
	{
		.hook		= ipv4_nat_in,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_RAW + 1,
	},
	{
		.hook		= ipv4_nat_out,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
};

static char *parse_addr(const char *input, __be32 *from, __be32 *to)
{
	char *p1, *p2;
	size_t length = strlen(input);
	
	if (!(p1 = memchr(input, ' ', length))) {
		return NULL;
	}

	if (!(p2 = memchr(p1 + 1, ' ', length - (p1 + 1 - input)))) {
		return NULL;
	}

	if (!(in4_pton(input, p1 - input, (u8 *)from, ' ', NULL))
			|| !(in4_pton(p1 + 1, p2 - p1 - 1, (u8 *)to, ' ', NULL))) {
		return NULL;
	}

	return ++p2;
}

static char *parse_port(char *input, __be16 *from, __be16 *to)
{
	char *p1;
	size_t length = strlen(input);
	size_t delta = 0;
	char tmp[8] = {0};
	__be16 res;

	/*portfrom portto*/

	if (!(p1 = memchr(input, ' ', length))) {
		return NULL;
	}

	delta = p1 - input;
	memcpy(tmp, input, delta);
	res = skip_atos(tmp);
	if (!res) {
		return NULL;
	}
	*from = htons(res);
	
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, p1+1, length-delta);
	res = skip_atos(tmp);
	if (!res) {
		return NULL;
	}
	*to = htons(res);


	return p1;
}

static int add_remove_nat_entry(struct static_nat_entry *ent,
								__be32 from, __be32 to,
								__be16 from_port, __be16 to_port,
								u8 dir,
								u8 proto,
								struct net_device *dev,
								u8 opt)
{
	int ret = 0;
	__be32 normal, reverse;
	struct map_result mres;
	if (opt == ENTRY_ADD) {
		if (!ent) {
			ret = -EINVAL;
			goto out;
		}
		ent->proto = proto;

		/* 计算原始项的hash桶位置 */
		normal = jhash_2words(from, (__be32)proto, 1);
		normal = normal%BUCKETS;

		/* 计算反转位置的hash桶位置 */
		reverse = jhash_2words(to, (__be32)proto, 1);
		reverse = reverse%BUCKETS;

		/*
		 *  设置key/value对
		 *  注意，反转类型的hnode其key/value也要反转
		 */
		ent->addr[0] = from;
		ent->addr[1] = to;

		ent->u.all[0] = from_port;
		ent->u.all[1] = to_port;

		/* 这是这个entry的type，用来区分生成的两条配置项 */
		ent->type = dir;
		ent->dev = dev;

		/* 初始化链表节点 */
		INIT_HLIST_NODE(&ent->node[DIR_SNAT]);
		INIT_HLIST_NODE(&ent->node[DIR_DNAT]);

		if (dir == DIR_SNAT) { /* 添加SNAT项，自动生成DNAT项 */
			/* 首先判断是否已经存在了 */
			if (!get_address_from_map(DIR_SNAT, from, from_port, proto, NAT_OPT_FIND, &mres, 0, dev) ||
					!get_address_from_map(DIR_SNAT, to, to_port, proto, NAT_OPT_FIND, &mres, 0, dev)) {
				ret = -EEXIST;
				goto out;
			}

			/* 落实到链表 */
			spin_lock(&nat_lock);
			hlist_add_head(&ent->node[DIR_SNAT], &src_list[normal]);
			hlist_add_head(&ent->node[DIR_DNAT], &dst_list[reverse]);
			spin_unlock(&nat_lock);
		} else if(dir == DIR_DNAT) { /* 添加DNAT项，自动生成SNAT项 */
			/* 首先判断是否已经存在了 */
			struct map_result mres;
			if (!get_address_from_map(DIR_DNAT, from, from_port, proto, NAT_OPT_FIND, &mres, 0, dev) ||
					!get_address_from_map(DIR_DNAT, to, to_port, proto, NAT_OPT_FIND, &mres, 0, dev)){
				ret = -EEXIST;
				goto out;
			}

			/* 落实到链表 */
			spin_lock(&nat_lock);
			hlist_add_head(&ent->node[DIR_DNAT], &dst_list[normal]);
			hlist_add_head(&ent->node[DIR_SNAT], &src_list[reverse]);
			spin_unlock(&nat_lock);
		} else {
			ret = -EINVAL;
			goto out;
		}
	} else if (opt == ENTRY_DEL) {
		u32 r1;

		if (dir == DIR_SNAT) {
			r1 = get_address_from_map(DIR_SNAT, from, from_port, proto, NAT_OPT_DEL, &mres, 0, dev);
			if (r1) {
				ret = -ENOENT;
				goto out;
			}
		} else if(dir == DIR_DNAT) {
			r1 = get_address_from_map(DIR_DNAT, from, from_port, proto, NAT_OPT_DEL, &mres, 0, dev);
			if (r1) {
				ret = -ENOENT;
				goto out;
			}
		} else {
			ret = -EINVAL;
			goto out;
		}
	} else {
		ret = -EINVAL;
		goto out;
	}
out:
		return ret;
}

static ssize_t static_nat_config_write(struct file *file, const char *buffer, size_t count, loff_t *unused)
{
	int ret = 0;
	size_t length = count;
	__be32 from, to;
	__be16 from_port = 0, to_port = 0;
	u8 proto = 0;
	char *buf = NULL;
	char *p, *pport, *last;
	struct static_nat_entry *ent;
	struct net_device *dev = NULL;

	if (length) {
		char *pp = (char *)(buffer + (length - 1)); 
		for (; (*pp < (char)32) || (*pp > (char)126); pp--) {
			if (length <= 0) {
				ret = -EINVAL;
				goto out;
			}
			length--;
		}
	} else {
		goto out;
	}

	buf = kzalloc((length + 1), GFP_ATOMIC);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(buf, buffer, length);
	if (!(p = parse_addr(buf + 1, &from, &to))) {
		ret = -EINVAL;
		goto out;
	}
	/*
	 * dev = dev_get_by_name(&init_net, $待解析的dev名字);
	 * */
	if (strstr(p, "tcp") && !strstr(p, "udp")) {
		proto = IPPROTO_TCP;
	} else if (strstr(p, "udp") && !strstr(p, "tcp")) {
		proto = IPPROTO_UDP;
	} else {
		/* 支持IPIP以及所有协议 */
		proto = IPPROTO_MAX - 1;	
	}
	

	if (((pport = strstr(p, "port-map")) != NULL) && 
			((last = parse_port(pport + strlen("port-map") + 1, &from_port, &to_port)) == NULL)) {
		ret = -EINVAL;
		goto out;
	}


	if ('+' == *buf) {
		ent = (struct static_nat_entry *)kzalloc(sizeof(struct static_nat_entry), GFP_KERNEL);
		if (!ent) {
			ret = -EFAULT;
			goto out;
		}

		if (strstr(p, "src")) { /* 添加SNAT项，自动生成DNAT项 */
			ret = add_remove_nat_entry(ent, from, to, from_port, to_port, DIR_SNAT, proto, dev, ENTRY_ADD);
			if (ret) {
				kfree(ent);
				goto out;
			}
		} else if(strstr(p, "dst")) { /* 添加DNAT项，自动生成SNAT项 */
			ret = add_remove_nat_entry(ent, from, to, from_port, to_port, DIR_DNAT, proto, dev, ENTRY_ADD);
			if (ret) {
				kfree(ent);
				goto out;
			}

		} else {
			ret = -EFAULT;
			kfree(ent);
			goto out;
		}

	} else if ('-' ==*buf) {

		if (strstr(p, "src")) {
			ret = add_remove_nat_entry(NULL, from, to, from_port, to_port, DIR_SNAT, proto, dev, ENTRY_DEL);
			if (ret) {
				goto out;
			}
		} else if(strstr(p, "dst")) {
			ret = add_remove_nat_entry(NULL, from, to, from_port, to_port, DIR_DNAT, proto, dev, ENTRY_DEL);
			if (ret) {
				goto out;
			}
		} else {
			ret = -EINVAL;
			goto out;
		}

	} else {
		ret = -EINVAL;
		goto out;
	}
	
	ret = count;
out:
	kfree(buf);
	return ret;
}

static ssize_t static_nat_config_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int len = 0;
	static int done = 0;
	int i;
	char from[15], to[15];
	char from_port[8], to_port[8];
	char *kbuf_to_avoid_user_space_memory_page_fault = NULL;

/* 每一行的最大长度 */
#define MAX_LINE_CHARS	128

	if (done) {
		done = 0;
		goto out;
	}
	
	/*
	 * 分配一块内核内存，为了避免直接操作用户内存而引发页面调度，
	 * 页面调度会导致睡眠切换，而我们操作的内容处在自旋锁的保护
	 * 下，所以不能切换！
	 */

	/*
	 * 问题：
	 * 我这里仅仅分配count大小的内存，是因为这个版本不支持多次读，
	 * 只能一次读完。也许我应该学学seq read的方法。
	 */
	kbuf_to_avoid_user_space_memory_page_fault = kzalloc(count, GFP_KERNEL);
	if (!kbuf_to_avoid_user_space_memory_page_fault) {
		len = -ENOMEM;
		done = 1;
		goto out;
	}	

	spin_lock(&nat_lock);
	len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, "Source trans table:\n");
	if (len + MAX_LINE_CHARS > count) {
		goto copy_now;
	}
	for (i = 0; i < BUCKETS; i++) {
		struct hlist_node *iter, *tmp;
		struct static_nat_entry *ent;
		hlist_for_each_safe(iter, tmp, &src_list[i]) {
			ent = hlist_entry(iter, struct static_nat_entry, node[DIR_SNAT]);
			sprintf(from, "%pI4", (ent->type == DIR_SNAT)? &ent->addr[0]:&ent->addr[1]);
			sprintf(to, "%pI4", (ent->type == DIR_SNAT)? &ent->addr[1]:&ent->addr[0]);
			if (ent->u.all[0] && ent->u.all[1]) {
				sprintf(from_port, "%d", ntohs((ent->type == DIR_SNAT)? ent->u.all[0]:ent->u.all[1]));
				sprintf(to_port, "%d", ntohs((ent->type == DIR_SNAT)? ent->u.all[1]:ent->u.all[0]));
				len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, 
							"From:%-15s To:%-15s    [%s %s] Port map[From:%-5s To:%-5s] [%s] [Bytes:%u  Packet:%u]\n", 
								from, 
								to, 
								(ent->proto == IPPROTO_TCP)?
											"TCP":
											(ent->proto == IPPROTO_UDP)?"UDP":"ALL",
								(ent->type == DIR_SNAT)?"STATIC":"AUTO",
								from_port, 
								to_port, 
								(ent->dev == NULL)?"all":ent->dev->name,
								ent->acct[DIR_SNAT].nat_bytes,
								ent->acct[DIR_SNAT].nat_packets);
			} else {
				len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, 
							"From:%-15s To:%-15s    [%s %s] [%s] [Bytes:%u  Packet:%u]\n", 
								from, 
								to, 
								(ent->proto == IPPROTO_TCP)?
											"TCP":
											(ent->proto == IPPROTO_UDP)?"UDP":"ALL",
								(ent->type == DIR_SNAT)?"STATIC":"AUTO",
								(ent->dev == NULL)?"all":ent->dev->name,
								ent->acct[DIR_SNAT].nat_bytes,
								ent->acct[DIR_SNAT].nat_packets);
			}

			if (len + MAX_LINE_CHARS > count) {
				goto copy_now;
			}
		} 
	}
	len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, "\nDestination trans table:\n");
	if (len + MAX_LINE_CHARS > count) {
		goto copy_now;
	}
	for (i = 0; i < BUCKETS; i++) {
		struct hlist_node *iter, *tmp;
		struct static_nat_entry *ent;
		hlist_for_each_safe(iter, tmp, &dst_list[i]) {
			ent = hlist_entry(iter, struct static_nat_entry, node[DIR_DNAT]);
			sprintf(from, "%pI4", (ent->type == DIR_DNAT)? &ent->addr[0]:&ent->addr[1]);
			sprintf(to, "%pI4", (ent->type == DIR_DNAT)? &ent->addr[1]:&ent->addr[0]);
			if (ent->u.all[0] && ent->u.all[1]) {
				sprintf(from_port, "%d", ntohs((ent->type == DIR_DNAT)? ent->u.all[0]:ent->u.all[1]));
				sprintf(to_port, "%d", ntohs((ent->type == DIR_DNAT)? ent->u.all[1]:ent->u.all[0]));
				len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, 
							"From:%-15s To:%-15s    [%s %s] Port map[From:%-5s To:%-5s] [%s] [Bytes:%u  Packet:%u]\n", 
								from, 
								to, 
								(ent->proto == IPPROTO_TCP)?
											"TCP":
											(ent->proto == IPPROTO_UDP)?"UDP":"ALL",
								(ent->type == DIR_DNAT)?"STATIC":"AUTO",
								from_port, 
								to_port, 
								(ent->dev == NULL)?"all":ent->dev->name,
								ent->acct[DIR_DNAT].nat_bytes,
								ent->acct[DIR_DNAT].nat_packets);
			} else {
				len += sprintf(kbuf_to_avoid_user_space_memory_page_fault + len, 
							"From:%-15s To:%-15s    [%s %s] [%s] [Bytes:%u  Packet:%u]\n", 
								from, 
								to, 
								(ent->proto == IPPROTO_TCP)?
											"TCP":
											(ent->proto == IPPROTO_UDP)?"UDP":"ALL",
								(ent->type == DIR_DNAT)?"STATIC":"AUTO",
								(ent->dev == NULL)?"all":ent->dev->name,
								ent->acct[DIR_DNAT].nat_bytes,
								ent->acct[DIR_DNAT].nat_packets);
			}

			if (len + MAX_LINE_CHARS > count) {
				goto copy_now;
			}
		} 
	}
copy_now:
	spin_unlock(&nat_lock);
	done = 1;
	/* 这里已经解除自旋锁 */
	if (copy_to_user(buf, kbuf_to_avoid_user_space_memory_page_fault, len))  {
		len = EFAULT;
		goto out;
	}
	
out:
	if (kbuf_to_avoid_user_space_memory_page_fault) {
		kfree(kbuf_to_avoid_user_space_memory_page_fault);
	}
	return len;
}

static const struct file_operations static_nat_file_ops = {
	.owner		= THIS_MODULE,
	.read		= static_nat_config_read,
/* 由于有了iptables接口，为了不产生两个写接口的联动问题，特意封掉了procfs的write接口 
 *	.write		= static_nat_config_write,
 */
};

/***************************************************************************************************************************/
/* 以下就是iptables接口了，我只是为了迎合它的语法而已，事实上static 2-way nat的规则中，matches完全不起作用，
 * 甚至就连PREROUTING/POSTROUTING都完全不起作用，我的目的仅仅是将其设置进内核而已。因此起作用的只有target。
 * 这是有原因的，因为我只是做一个纯粹的，无状态德，理所当然的，匹配地址端口即无条件转换的NAT，如果使用match
 * 将达不到这个要求，试想，如果有-i参数匹配网卡，那么反向的包怎么匹配，你不得不写两条规则，xtables-addons里面
 * 的RAWNAT似乎不是很完全，因此我要自己搞一个。
 * 事实上，我只是利用了target结构体的checkentry/destroy回调函数，在checkentry中添加规则，在destroy中删除规则，
 * 而所谓的规则也并不是指iptables规则，iptables只是起到一个stub的作用。
 * 以下是一些规则样例：
 * 1.做源地址转换，将源IP地址为192.168.184.1的包的源地址转换为192.168.184.2，反方向的包自动完成目标地址转换：
 *   iptables -t nat -A PREROUTING -j STATIC-2-WAY-NAT --mapaddr 192.168.184.1-192.168.184.2 --type src 
 * 2.做目标地址转换，仅限于UDP协议，将目标IP地址为192.168.184.3的包的目标地址转换为192.168.184.4，反方向包自动做源地址转换：
 *   iptables -t nat -A PREROUTING -j STATIC-2-WAY-NAT --mapaddr 192.168.184.3-192.168.184.4 --type dst --proto udp
 * 3.做目标地址转换，仅限于TCP协议，解释同上，添加了一个端口映射：
 *   iptables -t nat -A PREROUTING -j STATIC-2-WAY-NAT --mapaddr 1.1.1.5-1.6.8.6 --type dst --proto tcp \
 * --mapport 1234-80
 * 4.以下规则的所有matches无效，起不到限制规则匹配的作用：
 *   iptables -t nat -A PREROUTING -i eth0 -p icmp -d 1.2.3.4 -j STATIC-2-WAY-NAT ...
 */
/***************************************************************************************************************************/


/* 该链表保存了所有的当前iptales static nat规则 */
LIST_HEAD(curr_entrys);
DEFINE_SPINLOCK(curr_entrys_lock);

/*
 * 引入下面的数据结构加入curr_entrys是有超级原因的。这是因为我必须维护两个链表。
 * src_list/dst_list维护的是查找node，而entrys维护的则是iptables的规则node，为什么
 * iptables的规则node不能重用src_list/dst_list呢？因为iptables允许添加两条多条相同
 * 的规则。
 * 因此必须采用引用计数的方式。关于这么做的原因还有一个因素，那就是iptables添加删除
 * 规则时背后的操作：
 * 添加规则：
 *		1.开辟一块新的可以容纳新规则的内存空间(比原来的同一target空间大一个entry)；
 *		2.将老的规则全部copy到新的内存空间，新规则append到最后或者insert到中间(copy老规则时需预留间隙)；
 *		3.依次调用新内存空间所有entry的checkentry回调函数(失败则回退，略)；
 *		4.如果成功则调用老规则内存空间所有entry的destroy回调函数；
 *		5.释放老规则的内存空间；
 *
 *		各个步骤示意图如下所示(o:old  n:new)：
 *
 *			老规则空间：			o -1-  -2-  -3-
 *
 *			新规则空间：			ALLOC
 *									n ---  ---  ---  ---
 *
 *			拷贝老规则到新空间：	n -1-  -2-  -3-  ---
 *
 *			设置新规则：			n -1-  -2-  -3-  -4-
 *
 *			调用1-4的checkentry：	->chk->chk->chk->chk
 *									n -1-  -2-  -3-  -4-
 *
 *			destroy老空间的规则：	->dsy->dsy->dsy
 *									o -1-  -2-  -3- 
 *
 *			释放老规则空间：		FREE	
 *									o -1-  -2-  -3- 
 *	删除规则：
 *		和添加规则一样。
 *
 *	之所以每次添加规则都要触动统一target所有的既有规则，是因为iptables规则在内存中是连续存放的，
 *	一开始的时候并不知道数量，因此只能在每次添加新规则的时候重新分配大一个entry的空间，然后拷贝，
 *	最终释放老地址空间。
 */
struct entry_node {
	struct list_head list;
	atomic_t refcnt;
	struct net_device *dev;
	__be32 from, to;
	__be16 port_from, port_to;
	u8 proto;
	u8 dir;
};

static void entry_insert(struct entry_node *enode)
{
	spin_lock_bh(&curr_entrys_lock);
	list_add_tail(&enode->list, &curr_entrys);
	spin_unlock_bh(&curr_entrys_lock);
}

static struct entry_node *entry_alloc(__be32 from, __be32 to,
										__be16 port_from, __be16 port_to,
										u8 proto, 
										u8 dir,
										struct net_device *dev)
{
	struct entry_node *node = kzalloc(sizeof(struct entry_node), GFP_KERNEL);
	if (!node) {
		return NULL;
	}

	if (dev) {
		dev_hold(dev);
	}
	node->dev = dev;
	node->from = from;
	node->to = to;
	node->port_from = port_from;
	node->port_to = port_to;
	node->proto = proto;
	node->dir = dir;
	INIT_LIST_HEAD(&node->list);
	atomic_set(&node->refcnt, 1);
	return node;
}

static bool check_and_use(__be32 from, __be32 to,
							__be16 port_from, __be16 port_to,
							u8 proto,
							u8 dir,
							struct net_device *dev)
{
	bool ret = false;
	struct entry_node *i;
	spin_lock_bh(&curr_entrys_lock);
	if (!list_empty(&curr_entrys)) {
		list_for_each_entry(i, &curr_entrys, list) {
			if (i->from == from &&
				i->to == to &&
				i->port_from == port_from &&
				i->port_to == port_to &&
				i->proto == proto &&
				i->dir == dir &&
				i->dev == dev) {
				atomic_inc(&i->refcnt);
				ret = true;
			}
		}
	}
	spin_unlock_bh(&curr_entrys_lock);
	return ret;
}

static bool check_and_put(__be32 from, __be32 to,
							__be16 port_from, __be16 port_to,
							u8 proto,
							u8 dir,
							struct net_device *dev)
{
	bool ret = false;
	struct entry_node *i, *tmp;
	spin_lock_bh(&curr_entrys_lock);
	if (!list_empty(&curr_entrys)) {
		list_for_each_entry_safe(i, tmp, &curr_entrys, list) {
			if (i->from == from &&
				i->to == to &&
				i->port_from == port_from &&
				i->port_to == port_to &&
				i->proto == proto &&
				i->dir == dir && 
				i->dev == dev) {
				if (atomic_dec_and_test(&i->refcnt)) {
					list_del(&i->list);
					if (dev) {
						dev_put(dev);
					}
					kfree(i);
					ret = true;
				}
			}
		}
	}
	spin_unlock_bh(&curr_entrys_lock);
	return ret;
}

/* 
 * 理论上讲，下面这个函数应该是iptables的一条规则中所有match都匹配到之后要调用的函数，
 * 但是，你可以看到，在我的static 2-way nat中，它并不起任何作用。
 * 但是等等！
 * 它事实上取消了排在这个规则后面的statefull NAT的执行，因为它直接在nat表中ACCEPT了，
 * 这是什么，这是一个副作用，这个副作用竟然如此有用，以至于它已经可以模拟Cisco/H3C设备的
 * NAT了：静态NAT优先执行！
 *
 * 看来这是iptables相比procfs接口的一个特别有用的副作用了！
 */
static unsigned int
do_nothing(struct sk_buff *skb, const struct xt_target_param *par)
{
	return NF_ACCEPT;
}

static bool do_all_things_add(const struct xt_tgchk_param *par)
{
	int ret = true;
	__be32 from = 0, to = 0;
	__be16 from_port = 0, to_port = 0;
	u8 proto;
	u8 dir;
	struct static_nat_entry *ent = NULL;
	const struct xt_static_nat_tginfo *info = par->targinfo;
	struct net_device *dev;
/*
 * struct xt_static_nat_tginfo {
 * 	__be32 addr[DIR_NUM];
 *	__be16 port[DIR_NUM];
 *	u_int8_t proto;
 *	u_int8_t dir;
 * };
 */
	from = info->addr[0];
	to = info->addr[1];

	from_port = info->port[0];
	to_port = info->port[1];

	proto = info->proto;
	dir = info->dir;

	dev = dev_get_by_name(&init_net, info->dev);
	
	/* 只有在链表中没有该entry的情况下才添加 */
	if (!check_and_use(from, to, from_port, to_port, proto, dir, dev)) {
		struct entry_node *enode = entry_alloc(from, to, from_port, to_port, proto, dir, dev);
		if (enode) {
			entry_insert(enode);
			ent = (struct static_nat_entry *)kzalloc(sizeof(struct static_nat_entry), GFP_KERNEL);
			if (!ent) {
				ret = false;
				goto out;
			}

			ret = add_remove_nat_entry(ent, from, to, from_port, to_port, dir, proto, dev, ENTRY_ADD);
			if (ret) {
				ret = false;
				kfree(ent);
				check_and_put(from, to, from_port, to_port, proto, dir, dev);
				goto out;
			}
		} else {
			ret = false;
			goto out;
		}
	} else if (dev) {
		dev_put(dev);
	}

	ret = true;
out:
	return ret;
}

static void do_all_things_del(const struct xt_tgdtor_param *par)
{
	int ret = 0;
	__be32 from = 0, to = 0;
	__be16 from_port = 0, to_port = 0;
	u8 proto;
	u8 dir;
	const struct xt_static_nat_tginfo *info = par->targinfo;
	struct net_device *dev = NULL;

	from = info->addr[0];
	to = info->addr[1];

	from_port = info->port[0];
	to_port = info->port[1];

	proto = info->proto;
	dir = info->dir;

	dev = dev_get_by_name(&init_net, info->dev);

	if (check_and_put(from, to, from_port, to_port, proto, dir, dev)) {

		ret = add_remove_nat_entry(NULL, from, to, from_port, to_port, dir, proto, dev, ENTRY_DEL);
		if (ret) {
			goto out;
		}
	}
out:
	if (dev) {
		dev_put(dev);
	}
	return;
}

static struct xt_target static_nat_tg_reg[] __read_mostly = {
	{
		.name       = "STATIC-2-WAY-NAT",
		.family     = NFPROTO_IPV4,
		.target     = do_nothing,
		.table		= "nat",
		.targetsize = XT_ALIGN(sizeof(struct xt_static_nat_tginfo)),
		.checkentry = do_all_things_add,
		.destroy	= do_all_things_del,
		.hooks		= (1 << NF_INET_POST_ROUTING) |
							  (1 << NF_INET_PRE_ROUTING),
		.me         = THIS_MODULE,
	},
};

static int __init nf_static_nat_init(void)
{
	int ret = 0;
	int i;

	src_list = kzalloc(sizeof(struct hlist_head) * BUCKETS, GFP_KERNEL);
	if (!src_list) {
		ret = -ENOMEM;
		goto out;
	}
	dst_list = kzalloc(sizeof(struct hlist_head) * BUCKETS, GFP_KERNEL);
	if (!dst_list) {
		ret = -ENOMEM;
		goto out;
	}

	ret = nf_register_hooks(ipv4_nat_ops, ARRAY_SIZE(ipv4_nat_ops));
	if (ret < 0) {
		printk("nf_nat_ipv4: can't register hooks.\n");
		goto out;
	}

	ret = xt_register_targets(static_nat_tg_reg, ARRAY_SIZE(static_nat_tg_reg));
	if (ret < 0) {
		printk("nf_nat_ipv4: can't register targets.\n");
		goto out;
	}

	if (!proc_create("static_nat", 0644, init_net.proc_net, &static_nat_file_ops)) {
        ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < BUCKETS; i++) {
		INIT_HLIST_HEAD(&src_list[i]);
		INIT_HLIST_HEAD(&dst_list[i]);
	}
	return ret;
out:
	if (src_list) {
		kfree(src_list);
	} 
	if (dst_list) {
		kfree(dst_list);
	} 

	return ret;
}

static void __exit nf_static_nat_fini(void)
{
	int i;

	remove_proc_entry("static_nat", init_net.proc_net);
	xt_unregister_targets(static_nat_tg_reg, ARRAY_SIZE(static_nat_tg_reg));
	nf_unregister_hooks(ipv4_nat_ops, ARRAY_SIZE(ipv4_nat_ops));

	spin_lock(&nat_lock);
	for (i = 0; i < BUCKETS; i++) {
		struct hlist_node *iter, *tmp;
		struct static_nat_entry *ent;
		hlist_for_each_safe(iter, tmp, &src_list[i]) {
			ent = hlist_entry(iter, struct static_nat_entry, node[0]);
			hlist_del(&ent->node[DIR_SNAT]);
			hlist_del(&ent->node[DIR_DNAT]);
			kfree(ent);
		} 
	}
	spin_unlock(&nat_lock);
	if (src_list) {
		kfree(src_list);
	} 
	if (dst_list) {
		kfree(dst_list);
	} 
}

module_init(nf_static_nat_init);
module_exit(nf_static_nat_fini);

MODULE_DESCRIPTION("STATIC two-way NAT");
MODULE_AUTHOR("marywangran@126.com");
MODULE_LICENSE("GPL");
