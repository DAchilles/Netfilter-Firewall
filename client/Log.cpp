#include "head.h"
#include <iostream>
#include <string>

Log::Log(char *data, int offset) {
    src_ip = byteToInt(data, offset);
    dst_ip = byteToInt(data, offset + 4);
    src_port = byteToInt(data, offset + 8);
    dst_port = byteToInt(data, offset + 12);
    protocol = byteToInt(data, offset + 16);
    action = byteToInt(data, offset + 20);

}

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
