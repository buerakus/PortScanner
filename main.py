import logging
import sys
from scapy.all import *
from scapy.layers.inet import TCP, IP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 3:
    print("The format is: main.py targetIP port_file_path")
    sys.exit(0)

target_ip = str(sys.argv[1])
port_file_path = sys.argv[2]

print("Scanning {} for TCP ports".format(target_ip))

with open(port_file_path, 'r') as port_file:
    ports = port_file.read().split(', ')

for port in ports:
    packet = IP(dst=target_ip) / TCP(dport=int(port), flags='S')
    response = sr1(packet, timeout=2, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print("Port {} is open!".format(port))
        if response:
            sr(IP(dst=target_ip) / TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=0)

print("Scan is complete!")
