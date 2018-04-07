#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    name = "SwitchTrace"
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0),
                  IntField("enq_timestamp", 0),
                  IntField("deq_timedelta", 0),
                  BitField("ingress_global_timestamp", 0, 48)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
    name = "MRI"
    fields_desc = [ ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    bind_layers(UDP, MRI, dport=5000)
    bind_layers(UDP, MRI, sport=5000)
    iface = 'h2-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 5000", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
