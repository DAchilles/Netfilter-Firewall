#include "head.h"
#include <iostream>
#include <string>

Rule::Rule() {
    src_ip = 0;
	dst_ip = 0;
	src_mask = 0;
	dst_mask = 0;
	src_port = ANY;
	dst_port = ANY;
	protocol = ANY;
	action = 1;
	log = 0;
}

Rule::Rule(char *data, int offset) {
    src_ip = byteToInt(data, offset);
	dst_ip = byteToInt(data, offset + 4);
	src_mask = byteToInt(data, offset + 8);
	dst_mask = byteToInt(data, offset + 12);
	src_port = byteToInt(data, offset + 16);
	dst_port = byteToInt(data, offset + 20);
	protocol = byteToInt(data, offset + 24);
	action = byteToInt(data, offset + 28);
	log = byteToInt(data, offset + 32);
}

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
    
    ret += "src_ip:" + ipToStr(src_ip) + "\t";
    ret += "dst_ip:" + ipToStr(dst_ip) + "\t";
    ret += "src_mask:" + ipToStr(src_mask) + "\t";
    ret += "dst_mask:" + ipToStr(dst_mask) + "\t";
    ret += "src_port:" + std::to_string(src_port) + "\t";
    ret += "dst_port:" + std::to_string(dst_port) + "\t";
    ret += "protocol:" + ptcToStr(protocol) + "\t";
    ret += "act:" + toAct(action) + "\t";
    ret += "log:" + toLog(log) + "\n";

    std::cout << ret;
}
