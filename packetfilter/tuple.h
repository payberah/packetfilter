#ifndef _TUPLE_H
#define _TUPLE_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define BUF_LEN 100
struct Rule {
    u_int32_t srcIp;
    u_int32_t dstIp;
    u_int16_t srcPort;
    u_int16_t dstPort;
    u_int8_t proto;
};

struct Filter {
    Rule rule;
    int deny;
};

struct Tuple {
    int srcIpLen;
    int dstIpLen;
    int srcPortLen;
    int dstPortLen;
    int protoLen;
};

struct TupleSpace {
    Tuple tuple;
    Filter filter[20];
};

void showRule(Rule rule);

//------------------------------------------------
class PacketFilter {
    int m_fd;
    TupleSpace m_tupleSpace[100];
    int m_eachTupleMember[100];
    int m_numOfMember;
    int m_position;

public:
    PacketFilter();
    void addTupleSpace(Filter filter);
    Tuple mapFilterToTuple(Rule rule);
    void sortTupleSpace();     
    int findPosition(Tuple tuple);
    void addList(int index, Tuple tuple, Filter filter);
    void showSpace();
    Filter findFilter(Rule packet);
    int openDevice();
    void writeToDevice();
    int closeDevice();
};

//------------------------------------------------
class Parse {
    ifstream m_fd;
    char m_word[BUF_LEN];
    char m_buf[BUF_LEN];
    int m_lineNum;
    int m_position;
    Filter m_filter;
    Tuple m_tuple;
    PacketFilter *m_ruleList;

public:
    Parse(PacketFilter *packetFilter);
    bool readConfFile(char *fileName);
    void clearText();
    bool extractWord();
    bool parseLine(); 
    void addToList();
};

#endif // _TUPLE_H
