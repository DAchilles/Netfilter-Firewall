#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>
#include <net/ip.h>

// 设备号
#define MYMAJOR	200
// 协议号
#define TCP			6
#define	UDP			17
#define ICMP		1
#define ANY			-1
#define ICMP_PORT	65530
// 定义常量
#define MAX_RULE_NUM	50
#define MAX_LOG_NUM		100
#define MAX_NAT_NUM 	1000
#define HASH_SIZE		1000001
#define CONNECT_TIME	60
// 字符设备操作符
#define OP_WRITE_RULE	0
#define OP_GET_CONNECT	1
#define OP_GET_LOG		2
#define OP_GET_NAT		3



// 整型IP转x.x.x.x形式
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[3], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[0]

//设备定义
dev_t	devID;
struct cdev 	cdev;
struct class    *D_class;
struct device   *D_device;

// 规则结构
typedef struct {
    unsigned src_ip;
	unsigned dst_ip;
	unsigned src_mask;
	unsigned dst_mask;
	int src_port;
	int dst_port;
	int protocol;
	int action;
	int log;
} Rule;
// 规则表
static Rule rules[MAX_RULE_NUM];
// 规则数
static int rule_num = 0;

// 日志结构
typedef struct{
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int action;
} Log;
// 日志表
static Log logs[MAX_LOG_NUM];
// 日志数
static int log_num = 0;


// 连接结构
typedef struct con{
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int index;
	struct con *next;
}Connection;
// 连接链表的表头表尾
Connection conHead, conEnd;
// 连接表(Hash表)
char hashTable[HASH_SIZE]={0};
// 连接数
static int connection_num = 0;

// HASH锁
char hashLock = 0;
// 操作符（0写规则，1获取连接表，2获取日志，3获取NAT表）
static unsigned op_flag;
// 读写缓冲区
static char databuf[20480];


// hook注册
unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
// hook注销
unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
// 字符设备打开
static int datadev_open(struct inode *inode, struct file *filp);
// 字符设备读取
static ssize_t datadev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
// 字符设备写入
static ssize_t datadev_write(struct file *file, const char __user *user, size_t size, loff_t *ppos);
// 检查连接是否在连接表中，若在，返回-1，并更新存活时间，若不在，返回待插入的位置
int is_in_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol);
// 将连接信息插入到链表
void insert_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol,unsigned index);
// 记录日志
void add_log(Rule *p);
// 连接超时
void time_out(unsigned long x);
// 打印规则
void print_rules(void);
// 打印连接
void print_connections(void);
// Hash函数
static unsigned get_hash(int k);
// 真正负责检查过滤的工作函数
bool check_pkg(struct sk_buff *skb);

// hook注册结构体定义
static struct nf_hook_ops hook_in_ops = {
    .hook		= hook_in,				// hook处理函数
    .pf         = PF_INET,              // 协议类型
    .hooknum    = NF_INET_PRE_ROUTING,	// hook注册点
    .priority   = NF_IP_PRI_FIRST       // 优先级
};
// hook注销结构体定义
static struct nf_hook_ops hook_out_ops = {
    .hook		= hook_out,				// hook处理函数
    .pf         = PF_INET,              // 协议类型
    .hooknum    = NF_INET_POST_ROUTING,	// hook注册点
    .priority   = NF_IP_PRI_FIRST       // 优先级
};
// 连接超时结构体定义
static struct timer_list connect_timer = {
	.function = time_out
};
// 字符设备结构体定义(与用户程序信息交换)
static const struct file_operations datadev_fops = {
	.open		= datadev_open,			// 打开字符设备
	.read		= datadev_read,			// 读取字符设备
	.write		= datadev_write,		// 写入字符设备
};





unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	bool flag = check_pkg(skb);
	if (flag) {
		return NF_ACCEPT;
	} else {
		return NF_DROP;
	}
}

unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	bool flag = check_pkg(skb);
	if (flag) {
		return NF_ACCEPT;
	} else {
		return NF_DROP;
	}
}

static int datadev_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "datadev open\n");
	return 0;
}

static ssize_t datadev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
	int ret = 0;

	// 获取连接表
	if (op_flag == OP_GET_CONNECT) {
		// 等待开锁
		while (hashLock)
			;
		// 上锁
		hashLock = 1;
		
		// 返回值大小 = 连接数 * Connection大小
		ret = connection_num * (sizeof(Connection) - 4);
		if (ret > size) {
			printk("Connection: Read Overflow\n");
			return size;
		}

		Connection *p = conHead.next;
		int d, i=0;
		while (p != &conEnd) {
			d = p->src_ip;
			memcpy(&databuf[i * (sizeof(Connection) - 4)], &d, sizeof(unsigned));
			d = p->dst_ip;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 4], &d, sizeof(unsigned));
			d = p->src_port;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 8], &d, sizeof(int));
			d = p->dst_port;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 12], &d, sizeof(int));
			d = p->protocol;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 16], &d, sizeof(int));
			d = (int)hashTable[p->index];
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 20], &d, sizeof(unsigned));

			p = p->next;
			i++;
		}

		// 开锁
		hashLock = 0;
		copy_to_user(buf, databuf, ret);
		printk("Connection: Read %d bytes\n", ret);
	}
	// 获取日志表
	else if (op_flag == OP_GET_LOG) {
		ret = log_num * sizeof(Log);
		if (ret > size) {
			printk("Log: Read Overflow\n");
			return size;
		}

		memcpy(databuf, logs, ret);
		copy_to_user(buf, databuf, ret);
		printk("Log: Read %d bytes\n", ret);
	}
	// TODO:获取NAT表

	return ret;
}

static ssize_t datadev_write(struct file *file, const char __user *user, size_t size, loff_t *ppos) {
	if (size > 20480) {
		printk("Write Overflow\n");
		return 20480;
	}

	copy_from_user(databuf, user, size);

	int opt = 0x03 & databuf[size-1];

	if (opt == OP_WRITE_RULE) {
		op_flag = 0;
		rule_num = (size-1) / sizeof(Rule);
		printk("Get %d rules\n", rule_num);
		memcpy(rules, databuf+1, size-1);
		print_rules();
	}
	else if (opt == OP_GET_CONNECT) {
		op_flag = OP_GET_CONNECT;
		printk("Write Connections\n");
	}
	else if (opt == OP_GET_LOG) {
		op_flag = OP_GET_LOG;
		printk("Write Log\n");
	}
	else if (opt == OP_GET_NAT) {
		op_flag = OP_GET_NAT;
		printk("Write NAT\n");
	}

	return size;
}

int is_in_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol) {
	unsigned scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
	unsigned pos = get_hash(scode);

	// 等待开锁
	while(hashLock)
		;
	// 上锁
	hashLock = 1;
	// 连接存在，则更新连接时间
	if (hashTable[pos]) {
		// 更新连接时间
		hashTable[pos] = CONNECT_TIME;
		// 开锁
		hashLock = 0;
		// 返回-1
		return -1;
	}
	// 连接不存在，返回插入位置
	else {
		// 开锁
		hashLock = 0;
		return pos;
	}
}

void insert_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol,unsigned index) {
	Connection *p = (Connection *)kmalloc(sizeof(Connection), GFP_ATOMIC);
	
	p->src_ip = src_ip;
	p->dst_ip = dst_ip;
	p->src_port = src_port;
	p->dst_port = dst_port;
	p->protocol = protocol;
	p->index = index;
	p->next = conHead.next;
	conHead.next = p;

	while(hashLock)
		;
	hashLock = 1;
	hashTable[index] = CONNECT_TIME;
	++connection_num;
	hashLock = 0;
}

void add_log(Rule *p) {
	logs[log_num].src_ip 	= p->src_ip;
	logs[log_num].dst_ip 	= p->dst_ip;
	logs[log_num].src_port 	= p->src_port;
	logs[log_num].dst_port 	= p->dst_port;
	logs[log_num].protocol 	= p->protocol;
	logs[log_num].action 	= p->action;
	
	log_num++;
	if (log_num == MAX_LOG_NUM)
		log_num = 0;
}

void time_out(unsigned long x) {
	// p=首个连接，p0=链表头
	Connection *p = conHead.next, *p0 = &conHead;
	// 等待开锁
	while(hashLock)
		;
	// 上锁
	hashLock = 1;
	// 遍历链表减时间
	while(p != &conEnd) {
		hashTable[p->index]--;
		// 连接超时
		if (!hashTable[p->index]) {
			p0->next = p->next;
			kfree(p);
			connection_num--;
			p = p0->next;
		}
		else {
			p0 = p;
			p = p->next;
		}
	}
	// 开锁
	hashLock = 0;
	connect_timer.expires = jiffies + HZ;
	add_timer(&connect_timer);
}

void print_rules(void) {
	int i = 0;
	for(i=0; i<rule_num; ++i) {
		// srcIP & dstIP
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].src_ip), rules[i].src_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].dst_ip), rules[i].dst_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].src_mask), rules[i].src_mask);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].dst_mask), rules[i].dst_mask);

		// srcPort
		if (rules[i].src_port != ANY)
			printk("%d ", rules[i].src_port);
		else 
			printk("any ");
		// dstPort
		if (rules[i].dst_port != ANY)
			printk("%d ", rules[i].dst_port);
		else 
			printk("any ");
		// Protocol
		if (rules[i].protocol == TCP)
			printk("TCP ");
		else if (rules[i].protocol == UDP)
			printk("UDP ");
		else if (rules[i].protocol == ICMP)
			printk("ICMP ");
		
		// action
		if (rules[i].action)
			printk("accept ");
		else
			printk("deny ");
		
		// log
		if (rules[i].log)
			printk("loged\n");
		else 
			printk("unloged\n");
	}
}

void print_connections(void) {
	Connection *p = conHead.next;

	// 等待开锁
	while(hashLock)
		;
	// 上锁
	hashLock = 1;

	printk("************************************************\n");
	while (p != &conEnd) {
		// srcIP & dstIP
		printk(NIPQUAD_FMT " ", NIPQUAD(p->src_ip), p->src_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(p->dst_ip), p->dst_ip);
		// port
		printk("%u %u ", p->src_port, p->dst_port);
		// protocol
		if (p->protocol == TCP)
			printk("TCP ");
		else if (p->protocol == UDP)
			printk("UDP ");
		else if (p->protocol == ICMP)
			printk("ICMP ");
		// left time
		printk("%u\n", hashTable[p->index]);
		
		p = p->next;
	}
	printk("************************************************\n");

	// 开锁
	hashLock = 0;
}

static unsigned get_hash(int k) {
	unsigned a, b, c=4;
    a = b = 0x9e3779b9;
    a += k;
	a -= b; a -= c; a ^= (c>>13); 
	b -= c; b -= a; b ^= (a<<8); 
	c -= a; c -= b; c ^= (b>>13); 
	a -= b; a -= c; a ^= (c>>12);  
	b -= c; b -= a; b ^= (a<<16); 
	c -= a; c -= b; c ^= (b>>5); 
	a -= b; a -= c; a ^= (c>>3);  
	b -= c; b -= a; b ^= (a<<10); 
	c -= a; c -= b; c ^= (b>>15); 
  
    return c%HASH_SIZE;
}

bool check_pkg(struct sk_buff *skb) {
	if(!skb)
		return true;
	
	int i = 0;
	struct iphdr *ip = ip_hdr(skb);
	
	Rule pkg;
	pkg.src_ip = ntohl(ip->saddr);
	pkg.dst_ip = ntohl(ip->daddr);
	pkg.src_mask = pkg.dst_mask = 0xffffffff;

	int syn;
	if (ip->protocol == TCP) {
		struct tcphdr *tcp = tcp_hdr(skb);
		pkg.src_port = ntohs(tcp->source);
		pkg.dst_port = ntohs(tcp->dest);
		pkg.protocol = TCP;

		if ((tcp->syn) && (!tcp->ack))
			syn = 1;
		else
			syn = 0;
	}
	else if (ip->protocol == UDP) {
		struct udphdr *udp = udp_hdr(skb);
		pkg.src_port = ntohs(udp->source);
		pkg.dst_port = ntohs(udp->dest);
		pkg.protocol = UDP;

		syn = 2;
	}
	else if (ip->protocol == ICMP) {
		pkg.src_port = ICMP_PORT;
		pkg.dst_port = ICMP_PORT;
		pkg.protocol = ICMP;

		syn = 3;
	}
	else {
		return true;
	}

	int pos = is_in_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol);
	if (pos == -1) {
		return true;
	}
	else {
		for(i=0; i<rule_num; ++i) {
			if ((rules[i].src_ip & rules[i].src_mask) != (pkg.src_ip & rules[i].src_mask)) {
				continue;
			}
			if ((rules[i].dst_ip & rules[i].dst_mask) != (pkg.dst_ip & rules[i].dst_mask)) {
				continue;
			}
			if ((rules[i].protocol != ANY) && (rules[i].protocol != pkg.protocol)) {
				continue;
			}
			if ((rules[i].src_port != ANY) && (rules[i].src_port != pkg.src_port)) {
				continue;
			}
			if ((rules[i].dst_port != ANY) && (rules[i].dst_port != pkg.dst_port)) {
				continue;
			}

			if (rules[i].log) {
				printk("Match rule %d ", i);

				if (rules[i].action)
					printk("Accept\n");
				else
					printk("Drop\n");
				
				add_log(&rules[i]);
			}

			if (rules[i].action) {
				insert_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol, pos);
				return true;
			}
			else {
				return false;
			}
		}

		// 默认策略允许
		insert_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol, pos);
		return true;
	}
}

void addRules_test(void) {
	rules[rule_num].src_ip	= 0;
	rules[rule_num].src_mask= 0;
	rules[rule_num].dst_ip	= 3232241537;
	rules[rule_num].dst_mask= 0xFFFFFFFF;
	rules[rule_num].src_port= ANY;
	rules[rule_num].dst_port= 80;
	rules[rule_num].protocol= TCP;
	rules[rule_num].action	= false;
	rules[rule_num].log		= true;
	++rule_num;
}

static int __init myfirewall_init(void) {
	//创建连接表结构
	conHead.next = &conEnd;
	conEnd.next = NULL;

	cdev_init(&cdev, &datadev_fops);
	alloc_chrdev_region(&devID, 2, 255, "myfw");
	printk(KERN_INFO "MAJOR Number is %d\n", MAJOR(devID));
	printk(KERN_INFO "MINOR Number is %d\n", MINOR(devID));
	cdev_add(&cdev, devID, 255);

	D_class = class_create(THIS_MODULE, "Myfw");
	D_device = device_create(D_class, NULL, devID, NULL, "myfw");

	connect_timer.expires = jiffies + HZ;
	//初始化定时器
	init_timer(&connect_timer);
	//添加定时器，定时器开始生效
	add_timer(&connect_timer);
	
	nf_register_hook(&hook_in_ops);
	nf_register_hook(&hook_out_ops);

	printk("Myfw start\n");

	// addRules_test();
	print_rules();


	return 0;
}

static void __exit myfirewall_exit(void) {
	device_destroy(D_class, devID);
	class_destroy(D_class);
	cdev_del(&cdev);
	unregister_chrdev_region(devID, 255);
	del_timer(&connect_timer);

	nf_unregister_hook(&hook_in_ops);
	nf_unregister_hook(&hook_out_ops);

	printk("Myfw exit\n");
}

module_init(myfirewall_init);
module_exit(myfirewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DAchilles");
MODULE_DESCRIPTION("A firewall module");
MODULE_VERSION("V1.0");
