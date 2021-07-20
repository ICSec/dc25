#!/usr/bin/python

from scapy.all import *

host="127.0.0.1"

#thanks @snj https://gist.github.com/snj/9382c63ad49050e1b9ba
def knock(ports):
    print "[*] Knocking on ports"+str(ports)
    for dport in range(0, len(ports)):
        ip = IP(dst = host)
        SYN = ip/TCP(dport=ports[dport], flags="S", window=14600, options=[('MSS',1460)])
        send(SYN,verbose=0)

ports = [9264,11780,2059,8334]
knock(ports)
