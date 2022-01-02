#include "head.h"
#include "Util.cpp"

class Connection
{
public:
    unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int time;
   
    // void srcIP(std::string ip_str);
    // void dstIP(std::string ip_str);
   void print();
};

void Connection::print()
{
    std::string ret;
    
    ret += "src_ip:" + ipToStr(src_ip) + " ";
    ret += "dst_ip:" + ipToStr(dst_ip) + " ";
    ret += "src_port:" + std::to_string(src_port) + " ";
    ret += "dst_port:" + std::to_string(dst_port) + " ";
    ret += "protocol:" + ptcToStr(protocol) + " ";
    ret += "time:" + std::to_string(time);

    std::cout << ret << "\n";
}

