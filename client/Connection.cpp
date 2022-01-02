#include "head.h"
#include <iostream>
#include <string>

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

