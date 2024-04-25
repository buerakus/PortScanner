import logging
import sys
from scapy.all import *
from scapy.layers.inet import TCP, IP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 5:
    print("The format is : main.py targetIP startPort endPort bruteforce_file_path")
    sys.exit(0)

target_ip = str(sys.argv[1])
startingPort = int(sys.argv[2])
lastPort = int(sys.argv[3])
data_path = str(sys.argv[4])
print("Scanning " + target_ip + " for TCP ports")

if startingPort == lastPort:
    lastPort += 1

try:
    for x in range(startingPort,lastPort):
        packet = IP(dst=target_ip)/TCP(dport=x, flags='S')
        response = sr1(packet, timeout=0.5, verbose=0)
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print("Port " + str(x) + " is open!")
        sr(IP(dst=target_ip)/TCP(dport=response.sport,flags='R'), timeout=0.5, verbose=0)
except AttributeError:
    print("No more ports available!")

print("Scan is complete!")
