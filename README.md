# ARP Spoofing and DNS Spoofing Script

## Overview

This Python script is designed to perform ARP spoofing and DNS spoofing attacks using the `Scapy` library. The primary purpose of this tool is to intercept network traffic between a target device and its gateway (router) and perform DNS spoofing by redirecting specific domain requests to a fake IP address.

## Features

- **ARP Spoofing**: The script deceives the target device and the gateway by sending them malicious ARP responses, making them believe that the attacker's machine is the other device.
- **DNS Spoofing**: After ARP spoofing is established, DNS requests for a specific domain are intercepted and responded to with a fake IP address.
- **MAC Address Discovery**: The script automatically retrieves the MAC addresses of the target and gateway using ARP requests.

## Prerequisites

- Python 3.x
- Scapy (Install via `pip install scapy`)
- Administrative or root privileges (needed to send ARP packets)

## Usage

To run this script, you will need to provide the target IP address, gateway IP address, the domain you want to spoof, and the spoofed IP address (the IP address to which the domain will be redirected).

### Command Line Arguments

- `-t`, `--target-ip`: The IP address of the target device (victim).
- `-g`, `--gateway-ip`: The IP address of the gateway (usually the router).
- `-d`, `--domain`: The domain you want to spoof (e.g., `example.com`).
- `-s`, `--spoof-ip`: The IP address to which the domain should be spoofed.

### Example Command

```bash
sudo python3 arp_dns_spoof.py -t 192.168.1.10 -g 192.168.1.1 -d example.com -s 192.168.1.100
```

### Execution Steps:

1. **ARP Spoofing**: The script will start ARP spoofing in the background by pretending to be the gateway for the target and vice versa.
2. **DNS Spoofing**: The script sniffs DNS requests from the target and responds with the spoofed IP address if the domain matches.

## Script Breakdown

- **get_mac(ip)**: Sends ARP requests to retrieve the MAC address of a given IP address.
- **spoof_arp(target_ip, spoof_ip)**: Sends a malicious ARP response, tricking the target into thinking the attacker is the specified IP (either the gateway or the target).
- **restore_arp(target_ip, gateway_ip)**: Restores the ARP tables of the target and gateway to their original state.
- **spoof_dns(pkt, spoofed_ip, target_domain)**: Inspects DNS requests and sends a spoofed response with the fake IP if the request matches the target domain.
- **packet_sniffer(spoofed_ip, target_domain)**: Sniffs DNS packets and applies the `spoof_dns` function to relevant traffic.
- **arp_spoofing_attack(target_ip, gateway_ip)**: Continuously performs ARP spoofing between the target and the gateway.

## Important Notes

- This script is for educational purposes only. Unauthorized use of this script to attack networks or devices without consent is illegal and unethical.
- Ensure you have explicit permission to perform these actions on the target network.
  
## Stopping the Attack

To stop the script, press `CTRL+C`. The ARP tables will be restored to their original state to prevent disruption of the network.

## Limitations

- The script will only spoof a single domain.
- It requires root privileges to send ARP and DNS packets.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
