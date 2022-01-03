#include <string>

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

class Connection
{
public:
    unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int time;
   
	Connection(char *data, int offset);
   	void print();
};

class Log
{
public:
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int action;

	Log(char *data, int offset);
    void print();
};

class Rule
{
public:
    unsigned src_ip;
	unsigned dst_ip;
	unsigned src_mask;
	unsigned dst_mask;
	int src_port;
	int dst_port;
	int protocol;
	int action;
	int log;
    
	Rule();
	Rule(char *data, int offset);
    void srcIP(std::string ip_str);
    void dstIP(std::string ip_str);
    void srcMask(std::string ip_str);
    void dstMask(std::string ip_str);
    void print();

};

unsigned strToIp(std::string ip_str);
std::string ipToStr(unsigned ip);
unsigned strToPtc(std::string ptc_str);
std::string ptcToStr(unsigned ptc);
unsigned byteToInt(char *byte, int offset);
std::string toAct(int x);
std::string toLog(int x);

void getRules();
void getConnection();
void getLogs();
void printRules();
void printConnection();
void printLogs();
void addRule(std::string sip, std::string dip, std::string smask, std::string dmask, int sport, int dport, int protocol, int action, int log);
void commitRule();
void test();