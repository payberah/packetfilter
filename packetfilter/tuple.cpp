#include "tuple.h"

Parse::Parse(PacketFilter *packetFilter) {
    m_ruleList = packetFilter;
    m_lineNum = 0;
    m_position = 0;
}

//------------------------------------------------
bool Parse::readConfFile(char *fileName) {
    m_fd.open(fileName);
    if (m_fd.fail()) {
	cerr << "can not open file " << fileName << endl;
	return false;
    }
    
    while (1) {
	m_fd.getline(m_buf, BUF_LEN);
	if (m_fd.eof())
	    break;
	m_lineNum++;
	clearText();

	if (!parseLine()) {
	    cerr << "some error in line " << m_lineNum << " of " << fileName << "." << endl;
	    return false;
	}

	addToList();
    }

    return true;    	
}

//------------------------------------------------
void Parse::clearText() }
    int i, j;
    for (i = j = 0; m_buf[j] && m_buf[j] != '#'; j++) {
	if (m_buf[j] != ' ' && m_buf[j] != '\t')
	    m_buf[i++] = m_buf[j];
	else if (i && m_buf[i - 1] != ' ')
	    m_buf[i++] = m_buf[j];
    }

    m_buf[i] = 0;
}

//------------------------------------------------
bool Parse::extractWord() {
    if (m_buf[m_position] == ' ')
	m_position++;

    if (!m_buf[m_position])
	return false;

    int i;
    for (i = 0; m_buf[m_position] != ' ' && m_buf[m_position]; )
	m_word[i++] = m_buf[m_position++];

    m_word[i] = 0;

    return true;
}

//------------------------------------------------
bool Parse::parseLine() {
    m_position = 0;
    if (!extractWord())
	return false;

    if (!strcasecmp(m_word, "accept"))
	m_filter.deny = 0;
    else if (!strcasecmp(m_word, "deny"))
	m_filter.deny = 1;
    else
	return false;
    
    if (!extractWord()) // source ip address
	return false;
    else
	m_filter.rule.srcIp = inet_addr(m_word);

    if (!extractWord()) // destination ip address
	return false;
    else
	m_filter.rule.dstIp = inet_addr(m_word);
    
    if (!extractWord()) // source port address
	return false;
    else
	m_filter.rule.srcPort = atoi(m_word);

    if (!extractWord()) // destination port address
	return false;
    else
	m_filter.rule.dstPort = atoi(m_word);

    if (!extractWord()) // protocol type
	return false;
    else
	m_filter.rule.proto = atoi(m_word);
	
    return true;
}

//------------------------------------------------
void Parse::addToList() {
    m_ruleList->addTupleSpace(m_filter);
}

//------------------------------------------------
PacketFilter::PacketFilter() {
    int i;
    for (i = 0; i < 100; i++)
	m_eachTupleMember[i] = 0;

    m_numOfMember = 0;
    m_position = 0;
}

//------------------------------------------------
void PacketFilter::addTupleSpace(Filter filter) {
    Tuple tuple;
    int index;

    tuple = mapFilterToTuple(filter.rule);
    index = findPosition(tuple);
    if (index == m_position)
	m_position++;

    addList(index, tuple, filter);
}

//------------------------------------------------
Tuple PacketFilter::mapFilterToTuple(Rule rule) {
    int i;
    u_int8_t addr[4];
    Tuple tuple = {0, 0, 0, 0, 0};

    memcpy(addr, &rule.srcIp, 4);

    for (i = 0; i < 4; i++)
	if (addr[i] == 0)
	    tuple.srcIpLen += 8;

    tuple.srcIpLen = 32 - tuple.srcIpLen;
    memcpy(addr, &rule.dstIp, 4);

    for (i = 0; i < 4; i++)
	if (addr[i] == 0)
	    tuple.dstIpLen += 8;

    tuple.dstIpLen = 32 - tuple.dstIpLen;
    tuple.srcPortLen = rule.srcPort / 1000;
    tuple.dstPortLen = rule.dstPort / 1000;
    tuple.protoLen = rule.proto;

    return tuple;
}

//------------------------------------------------
int PacketFilter::findPosition(Tuple tuple) {
    int i;
    for (i = 0; i < m_position; i++) {
	if (tuple.srcIpLen == m_tupleSpace[i].tuple.srcIpLen &&
	    tuple.dstIpLen == m_tupleSpace[i].tuple.dstIpLen &&
	    tuple.srcPortLen == m_tupleSpace[i].tuple.srcPortLen &&
	    tuple.dstPortLen == m_tupleSpace[i].tuple.dstPortLen &&
	    tuple.protoLen == m_tupleSpace[i].tuple.protoLen)
	    return i;
    }

    return m_position;
}

//------------------------------------------------
void PacketFilter::addList(int index, Tuple tuple, Filter filter) {
    m_tupleSpace[index].filter[m_eachTupleMember[index]] = filter;
    m_tupleSpace[index].tuple = tuple;
    m_numOfMember++;
    m_eachTupleMember[index]++;
}

//------------------------------------------------
void PacketFilter::sortTupleSpace() {
    int i, j, temp;
    TupleSpace tempSpace;
    for (i = 0; i < m_position; i++) {
	for (j = i; j < m_position; j++) {
	    if ((m_tupleSpace[i].tuple.srcIpLen + m_tupleSpace[i].tuple.dstIpLen) < (m_tupleSpace[j].tuple.srcIpLen + m_tupleSpace[j].tuple.dstIpLen)) {
		tempSpace = m_tupleSpace[i];
		m_tupleSpace[i] = m_tupleSpace[j];
		m_tupleSpace[j] = tempSpace;
		
		temp = m_eachTupleMember[i];
		m_eachTupleMember[i] = m_eachTupleMember[j];
		m_eachTupleMember[j] = temp;    
	    }
	}
    }
}

//------------------------------------------------
void PacketFilter::showSpace() {
    int i, j;
    for (i = 0; i < m_position; i++) {
	printf("tuple%d: {%d %d %d %d %d}\n", i, m_tupleSpace[i].tuple.srcIpLen, m_tupleSpace[i].tuple.dstIpLen, m_tupleSpace[i].tuple.srcPortLen, m_tupleSpace[i].tuple.dstPortLen, m_tupleSpace[i].tuple.protoLen);
	for (j = 0; j < m_eachTupleMember[i]; j++) {
	    printf("src ip: %x   dst ip: %x   src port: %d   dst port: %d   proto: %d\n", 
		    m_tupleSpace[i].filter[j].rule.srcIp, 
		    m_tupleSpace[i].filter[j].rule.dstIp,
		    m_tupleSpace[i].filter[j].rule.srcPort,
		    m_tupleSpace[i].filter[j].rule.dstPort,
		    m_tupleSpace[i].filter[j].rule.proto);
	}

	printf("\n----------------------\n");
    }
}

//------------------------------------------------
int PacketFilter::openDevice() {
    return m_fd = open("/dev/test", O_RDWR);
}

//------------------------------------------------
void PacketFilter::writeToDevice() {
    int i, j;
    Filter emptyFilter = {{0, 0, 0, 0, 0}, 1};

    for (i = 0; i < m_position; i++) {
	write(m_fd, &(m_tupleSpace[i].tuple), sizeof(Tuple));
	for (j = 0; j < m_eachTupleMember[i]; j++)
    	    write(m_fd, &(m_tupleSpace[i].filter[j]), sizeof(Filter));
	write(m_fd, &emptyFilter, sizeof(Filter));
    }

    return;
}

//------------------------------------------------
int PacketFilter::closeDevice() {
    return close(m_fd);
}

//------------------------------------------------
void showRule(Rule rule) {
    printf("src ip: %x\n", rule.srcIp);
    printf("dst ip: %x\n", rule.dstIp);
    printf("src port: %d\n", rule.srcPort);
    printf("dst port: %d\n", rule.dstPort);
    printf("proto: %d\n", rule.proto);
}
