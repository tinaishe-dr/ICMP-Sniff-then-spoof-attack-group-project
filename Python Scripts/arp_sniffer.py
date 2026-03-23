#!/usr/bin/env python3
from scapy.all import *

def show(pkt):
    if pkt.haslayer(ARP):
        print("\n=== ARP Packet ===")
        pkt.show()

sniff(iface="eth0", filter="arp", prn=show)
