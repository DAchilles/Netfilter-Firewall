#include "head.h"
#include <iostream>
#include <string>

Connection::Connection(char *data, int offset) {
    src_ip = byteToInt(data, offset);
    dst_ip = byteToInt(data, offset + 4);
    src_port = byteToInt(data, offset + 8);
    dst_port = byteToInt(data, offset + 12);
    protocol = byteToInt(data, offset + 16);
    time = byteToInt(data, offset + 20);
}

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

