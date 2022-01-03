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

static string DEV_NAME  = "/dev/myfw";
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
    cout << "Get connection" << endl;
    char databuf[20480];
    ifstream inputKernel;
    inputKernel.open(DEV_NAME, ios::binary);

    // FIXME:将connection输入到List中
    int i=0;
    while (inputKernel.read(databuf, sizeof(Connection))) {
        Connection *con = new Connection(databuf, 0);
        connectionList.push_back(*con);

        if (++i == 10) {
            break;
        }
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
    cout << "Get logs" << endl;
    char databuf[20480];
    ifstream inputKernel;
    inputKernel.open(DEV_NAME, ios::binary);

    // FIXME:将Logs输入到List中
    int i=0;
    while (inputKernel.read(databuf, sizeof(Log))) {
        Log *log = new Log(databuf, 0);
        logList.push_back(*log);

        if (++i == 10) {
            break;
        }
    }
    inputKernel.close();
}

void printRules() {
    cout << "====================================================Rules===============================================" <<endl;
    for(int i=0; i<ruleList.size(); ++i) {
        ruleList[i].print();
    }
}

void printConnection() {
    cout << "==================================================Connection============================================" <<endl;
    for(int i=0; i<connectionList.size(); ++i) {
        connectionList[i].print();
    }
}

void printLogs() {
    cout << "=====================================================Logs===============================================" <<endl;
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

    cout << "Commit " << ruleList.size() << " rules" <<endl;
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

void help() {
    cout << "Usage: myFirewall [Options]" <<endl;
    cout << "\t-p, --print [Options] \n\t\tprint all data" << endl;
    // cout << "\t-a, --add <src_ip> <dst_ip> <src_mask> <dst_mask> <src_port> <dst_port> <protocol> <action> <log>" << endl;
    cout << "\t-a, --add <rule> \n\t\tadd a rule in database" << endl;
    cout << "\t-d, --del <index1, index2...> \n\t\tdel rule in index" << endl;
    cout << "\t-c, --commit \n\t\tcommit rules to kernel" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        help();
        return 0;
    }

    string fuc = argv[1];
    // printRules, printConnection, printLog
    if (fuc == "-p" || fuc == "--print") {
        if (argc == 2) {
            getRules();
            printRules();
            getConnection();
            printConnection();
            getLogs();
            printLogs();
        }
        else if (argc == 3) {
            string opt = argv[2];
            if (opt == "r" || opt == "rule" || opt == "rules") {
                getRules();
                printRules();
            }
            else if (opt == "c" || opt == "connection") {
                getConnection();
                printConnection();
            }
            else if (opt == "l" || opt == "log" || opt == "logs") {
                getLogs();
                printLogs();
            }
            else {
                help();
                return 0;
            }
        }
        else {
            help();
            return 0;
        }
    }
    // addRule
    else if (fuc == "-a" || fuc == "--add") {
        if (argc == 11) {
            string sip = argv[2], dip = argv[3];
            string smask = argv[4], dmask = argv[5];
            int sport = ANY, dport = ANY, ptc = ANY, act = 1, loged = 0;
            // src_port
            if (strcmp(argv[6], "ANY") == 0) {
                sport = ANY;
            } else {
                sport = atoi(argv[6]);
            }
            // dst_port
            if (strcmp(argv[7], "ANY") == 0) {
                dport = ANY;
            } else {
                dport = atoi(argv[7]);
            }

            // protocol
            ptc = strToPtc(argv[8]);
            // action
            act = atoi(argv[9]);
            // log
            loged = atoi(argv[10]);

            addRule(sip, dip, smask, dmask, sport, dport, ptc, act, loged);
            getRules();
            printRules();
        }
        else {
            help();
            return 0;
        }
    }
    // delRule
    else if (fuc == "-d" || fuc == "--del") {
        for (int i=2; i<argc; ++i) {
            int index = atoi(argv[i]);
            if (index > 0) {
                delRule(index - 1);
            }
        }
        getRules();
        printRules();
    }
    // commitRule
    else if ((argc == 2) && (fuc == "-c" || fuc == "--commit")) {
        commitRule();
        getRules();
        printRules();
    }
    else {
        help();
        return 0;
    }
    
    return 0;
}




