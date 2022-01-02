#include <iostream>
#include <algorithm>
#include <vector>

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

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