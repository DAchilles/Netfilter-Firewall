#include "head.h"

unsigned strToIp(std::string ip_str) {
    unsigned ip = 0;
    char *p, *str = new char[ip_str.size() + 1];
    strcpy(str, ip_str.c_str());
    
    p = strsep(&str, ".");
    while (p != NULL) {
        ip = ip<<8 | atoi(p);
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