#include "head.h"

#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <fstream>

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>


using namespace std;

vector<Rule> ruleList;
vector<Log> logList;
vector<Connection> connectionList;

static string DEV_NAME  = "testfile";
static string RULE_DB   = "rule.db";

void getRules() {
    ruleList.clear();
    
    // 从 "rule.db" 中读取规则
    char databuf[20480];
    ifstream inputFile;
    inputFile.open(RULE_DB, ios::binary);

    while (inputFile.read(databuf, sizeof(Rule))) {
        Rule *rule = new Rule(databuf, 0);
        ruleList.push_back(*rule);
    }
    inputFile.close();
}

void getConnection() {
    // 告诉内核：我要开始读取Connection
    ofstream outputKernel;
    outputKernel.open(DEV_NAME, ios::binary);
    outputKernel << OP_GET_CONNECT;
    outputKernel.close();

    // 开始读取Connection
    char databuf[20480];
    ifstream inputKernel;
    inputKernel.open(DEV_NAME, ios::binary);
    // inputKernel >> databuf;

    // 将connection输入到List中
    while (inputKernel.read(databuf, sizeof(Connection)))
    {
        Connection *con = new Connection(databuf, 0);
        connectionList.push_back(*con);
    }
    inputKernel.close();
}

void getLogs() {
    // 告诉内核：我要开始读取Logs
    ofstream outputKernel;
    outputKernel.open(DEV_NAME, ios::binary);
    outputKernel << OP_GET_LOG;
    outputKernel.close();

    // 开始读取Logs
    char databuf[20480];
    ifstream inputKernel;
    inputKernel.open(DEV_NAME, ios::binary);

    // 将Logs输入到List中
    while (inputKernel.read(databuf, sizeof(Log)))
    {
        Log *log = new Log(databuf, 0);
        logList.push_back(*log);
    }
    inputKernel.close();
}

void printRules() {
    for(int i=0; i<ruleList.size(); ++i) {
        ruleList[i].print();
    }
}

void printConnection() {
    for(int i=0; i<connectionList.size(); ++i) {
        connectionList[i].print();
    }
}

void printLogs() {
    for(int i=0; i<logList.size(); i++) {
        logList[i].print();
    }
}

void addRule(string sip, string dip, string smask, string dmask, int sport, int dport, int protocol, int action, int log) {
    Rule *rule = new Rule;

    rule->srcIP(sip);
    rule->dstIP(dip);
    rule->srcMask(smask);
    rule->dstMask(dmask);
    rule->src_port = sport;
    rule->dst_port = dport;
    rule->protocol = protocol;
    rule->action = action;
    rule->log = log;

    // ruleList.push_back(*rule);
    
    // 将新rule写入文件
    ofstream outputFile;
    outputFile.open(RULE_DB, ios::app);
    outputFile.write((char*)rule, sizeof(Rule));
    outputFile.close();
}

void delRule(int index) {
    // 先获取所有rules
    getRules();

    // 删除指定下标的rule
    ruleList.erase(ruleList.begin() + index);

    // 清空源文件
    ofstream fileout(RULE_DB, ios::trunc);

    // 写回到文件
    ofstream outputFile;
    outputFile.open(RULE_DB, ios::app);
    for(int i=0; i<ruleList.size(); ++i) {
        outputFile.write((char*)&ruleList[i], sizeof(Rule));
    }
    outputFile.close();
}

void commitRule() {
    // 先获取所有rules
    getRules();

    // 告诉内核：我要开始写Rules
    ofstream outputKernel;
    outputKernel.open(DEV_NAME, ios::binary);
    outputKernel << OP_WRITE_RULE;
    
    // 开始写Rules
    // char *writeBuf = new char[sizeof(Rule) * ruleList.size() + 1];
    for(int i=0; i<ruleList.size(); ++i) {
        outputKernel.write((char*)&ruleList[i], sizeof(Rule));
    }
    outputKernel.close();

    cout << "Commit " << ruleList.size() << " rules";
}

void test() {
    // addRule("0.1.2.3", "192.168.23.129", "0.0.0.0", "255.255.255.255", ANY, 80, TCP, 0, 1);
    // addRule("4.5.6.7", "192.168.23.129", "255.255.255.255", "255.255.255.255", ANY, ANY, ICMP, 1, 0);
    // addRule("8.9.10.11", "192.168.23.129", "0.0.0.0", "255.255.255.255", ANY, 80, TCP, 0, 1);
    // addRule("12.13.14.15", "192.168.23.129", "255.255.255.255", "255.255.255.255", ANY, ANY, ICMP, 1, 0);
    
    // delRule(0);
    // delRule(4);
    
    getRules();
    printRules();
}

int main(int argc, char* argv[]) {
    test();
}




