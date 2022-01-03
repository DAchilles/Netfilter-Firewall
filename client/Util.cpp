#include "head.h"
#include <iostream>
#include <string>
#include <cstring>


unsigned strToIp(std::string ip_str) {
    unsigned ip = 0;
    char *p, *str = new char[ip_str.size() + 1];
    strcpy(str, ip_str.c_str());
    
    p = strsep(&str, ".");
    while (p != NULL) {
        ip = ip<<8 | atoi(p);
        p = strsep(&str, ".");
    }

    return ip;
}

std::string ipToStr(unsigned ip) {
    std::string ip_str;
    
    ip_str += std::to_string((ip >> 24) & 0x000000ff) + ".";
    ip_str += std::to_string((ip >> 16) & 0x000000ff) + ".";
    ip_str += std::to_string((ip >> 8) & 0x000000ff) + ".";
    ip_str += std::to_string((ip) & 0x000000ff);

    return ip_str;
}

unsigned strToPtc(std::string ptc_str) {
    if (ptc_str == "TCP")
        return TCP;
    if (ptc_str == "UDP")
        return UDP;
    if (ptc_str == "ICMP")
        return ICMP;
    return ANY;
}

std::string ptcToStr(unsigned ptc) {
    if (ptc == TCP) 
        return "TCP";
    if (ptc == UDP)
        return "UDP";
    if (ptc == ICMP)
        return "ICMP";
    return "ANY";
}

unsigned byteToInt(char *byte, int offset) {
    unsigned x=0;
    for(int i=0; i<4; ++i) {
        x <<= 8;
        x |= (byte[offset + 3 - i] & 0xff);
    }
    return x;
}

std::string toAct(int x) {
    if (x) 
        return "Accept";
    return "Deny";
}

std::string toLog(int x) {
    if (x)
        return "Loged";
    return "Unloged";
}