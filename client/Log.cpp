#include "head.h"
#include <iostream>
#include <string>

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
