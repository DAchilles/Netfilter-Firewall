#include "head.h"
#include "Util.cpp"

class Rule
{
public:
    unsigned src_ip     = 0;
	unsigned dst_ip     = 0;
	unsigned src_mask   = 0;
	unsigned dst_mask   = 0;
	int src_port        = -1;
	int dst_port        = -1;
	int protocol        = -1;
	int action          = true;
	int log             = false;
    
    void srcIP(std::string ip_str);
    void dstIP(std::string ip_str);
    void srcMask(std::string ip_str);
    void dstMask(std::string ip_str);

    void print();

};

void Rule::srcIP(std::string ip_str) {
    src_ip = strToIp(ip_str);
}

void Rule::dstIP(std::string ip_str) {
    dst_ip = strToIp(ip_str);
}

void Rule::srcMask(std::string ip_str) {
    src_mask = strToIp(ip_str);
}

void Rule::dstMask(std::string ip_str) {
    dst_mask = strToIp(ip_str);
}


void Rule::print() {
    std::string ret;
    
    ret += "src_ip:" + ipToStr(src_ip) + " ";
    ret += "dst_ip:" + ipToStr(dst_ip) + " ";
    ret += "src_mask" + ipToStr(src_mask) + " ";
    ret += "dst_mask" + ipToStr(dst_mask) + " ";
    ret += "src_port:" + std::to_string(src_port) + " ";
    ret += "dst_port:" + std::to_string(dst_port) + " ";
    ret += "protocol:" + ptcToStr(protocol) + " ";
    ret += "act:" + std::to_string(action) + " ";
    ret += "log:" + std::to_string(log);

    std::cout << ret << "\n";
}
