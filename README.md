# DNS Spoofer

A Python-based DNS spoofing tool built using `scapy` and `netfilterqueue`. This tool allows you to spoof DNS responses to redirect users to a specific IP address. It works by intercepting and modifying DNS responses in a network.

> **Warning**: This tool is intended for educational purposes only. Unauthorized use of this tool on networks you do not own or have permission to test is illegal and unethical. Use this tool responsibly in a controlled, authorized environment.

## Features

- Captures DNS requests and spoofs the response for specified domains.
- Redirects DNS queries for specific domains to a specified IP address.
- Uses `netfilterqueue` to capture packets from a Linux-based firewall.

## Requirements

To run this tool, you need the following:

- **Python 3.x**
- **Linux-based system** (or virtual machine with Linux)
- **`scapy`** for packet manipulation
- **`netfilterqueue`** for capturing packets from the firewall

### Install Dependencies

1. Create a virtual environment and activate it:

   ```bash
   python3 -m venv env
   source env/bin/activate
   ```

2. Install the required Python libraries:

   ```bash
   pip install scapy netfilterqueue
   ```

## Usage

1. **Set up `iptables` rules** on your Linux system to capture DNS packets and forward them to the `netfilterqueue`. Run the following commands:

   - Forward incoming packets to the queue:
     ```bash
     sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
     ```

   - Capture outgoing packets:
     ```bash
     sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
     ```

   - Capture incoming packets:
     ```bash
     sudo iptables -I INPUT -j NFQUEUE --queue-num 0
     ```

2. **Run the Python script** with the target domains and spoofed IP addresses. Use the following command:

   ```bash
   sudo python3 dns_spoof.py -q 0 -t www.bing.com=10.0.2.16 www.example.com=10.0.2.17
   ```

   - Replace `www.bing.com` and `www.example.com` with the domains you want to spoof.
   - Replace `10.0.2.16` and `10.0.2.17` with the IP addresses you want to redirect the domains to.

3. **Flush `iptables` rules** after testing to ensure normal network traffic:

   ```bash
   sudo iptables --flush
   ```

## Example

To spoof DNS responses for `www.bing.com` and `www.example.com`, redirecting them to the IP address `10.0.2.16`, use the following command:

```bash
sudo python3 dns_spoof.py -q 0 -t www.bing.com=10.0.2.16 www.example.com=10.0.2.17
```

The tool will intercept DNS requests and respond with a spoofed IP address for these domains.

### Output Example

```
[+] Spoofing DNS request for www.bing.com
[+] Spoofing DNS request for www.example.com
```

## Legal Disclaimer

This tool is intended for **educational purposes only**. Unauthorized use of this tool on networks you do not own or have permission to test may violate laws and could result in severe consequences. Only use this tool in a legal, authorized environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```

### Key Sections:
- **Introduction**: Describes what the tool does and emphasizes the legal disclaimer.
- **Features**: Highlights the tool's core features.
- **Requirements**: Lists Python 3.x, Linux, `scapy`, and `netfilterqueue` as necessary tools.
- **Usage**: Explains how to set up `iptables` and run the Python script with target domains and IPs.
- **Example**: Provides an example of how to run the script.
- **Legal Disclaimer**: Warns about using the tool in a legal and ethical manner.
- **License**: The MIT license gives users freedom to use and modify the code.
