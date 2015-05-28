#include "tuple.h"

main() {
    PacketFilter pf;
    Parse parse(&pf);
    parse.readConfFile("rule.txt");
    pf.sortTupleSpace();
    pf.showSpace();
    pf.openDevice();
    pf.writeToDevice();
    pf.closeDevice();
}
