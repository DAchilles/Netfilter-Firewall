#include "head.h"
#include "Util.cpp"

class Log
{
public:
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int action;

    // void srcIP(std::string ip_str);
    // void dstIP(std::string ip_str);

    void print();
};

// void Log::srcIP(std::string ip_str) {
//     unsigned ip = 0;
//     char *p, *str = new char[ip_str.size() + 1];
//     strcpy(str, ip_str.c_str());
//     p = strsep(&str, ".");
//     while (p != NULL) {
//         ip = ip<<8 | atoi(p);
//     }
//     src_ip = ip;
// }

// void Log::dstIP(std::string ip_str) {
//     unsigned ip = 0;
//     char *p, *str = new char[ip_str.size() + 1];
//     strcpy(str, ip_str.c_str());
//     p = strsep(&str, ".");
//     while (p != NULL) {
//         ip = ip<<8 | atoi(p);
//     }
//     dst_ip = ip;
// }

// std::string Log::srcIP() {
//     std::string ip;

//     ip += std::to_string((src_ip >> 24) & 0x000000ff) + ".";
//     ip += std::to_string((src_ip >> 16) & 0x000000ff) + ".";
//     ip += std::to_string((src_ip >> 8) & 0x000000ff) + ".";
//     ip += std::to_string((src_ip) & 0x000000ff);

//     return ip;
// }

// std::string Log::dstIP() {
//     std::string ip;

//     ip += std::to_string((dst_ip >> 24) & 0x000000ff) + ".";
//     ip += std::to_string((dst_ip >> 16) & 0x000000ff) + ".";
//     ip += std::to_string((dst_ip >> 8) & 0x000000ff) + ".";
//     ip += std::to_string((dst_ip) & 0x000000ff);

//     return ip;
// }

// std::string Log::ptc(){
//     std::string str;
    
//     if (protocol == TCP) {
//         str = "TCP";
//     } else if (protocol == UDP) {
//         str = "UDP";
//     } else if (protocol == ICMP) {
//         str = "ICMP";
//     } else {
//         str = "ANY";
//     }

//     return str;
// }

void Log::print() {
    std::string ret;
    
    ret += "src_ip:" + ipToStr(src_ip) + " ";
    ret += "dst_ip:" + ipToStr(dst_ip) + " ";
    ret += "src_port:" + std::to_string(src_port) + " ";
    ret += "dst_port:" + std::to_string(dst_port) + " ";
    ret += "protocol:" + ptcToStr(protocol) + " ";
    ret += "act:" + std::to_string(action);

    std::cout << ret << "\n";
}
