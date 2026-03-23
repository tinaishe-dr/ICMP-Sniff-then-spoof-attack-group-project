#!/usr/bin/env python3
from scapy.all import *

def show_packet(pkt):
    print("\n=== ICMP Packet Captured ===")
    pkt.show()

sniff(iface="eth0", filter="icmp", prn=show_packet)