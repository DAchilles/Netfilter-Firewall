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
    
    ret += "src_ip:" + ipToStr(src_ip) + "\t";
    ret += "dst_ip:" + ipToStr(dst_ip) + "\t";
    ret += "src_port:" + std::to_string(src_port) + "\t";
    ret += "dst_port:" + std::to_string(dst_port) + "\t";
    ret += "protocol:" + ptcToStr(protocol) + "\t";
    ret += "act:" + toAct(action) + "\n";

    std::cout << ret;
}
