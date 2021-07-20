from scapy.all import *

ap_list = []
evil_packets = []

a = rdpcap("../PCAPs/OOBackdoor/lvl1exfil.pcapng")

for i in range(len(a)):
    pkt = a[i]
    if (pkt.haslayer(Dot11)) and (pkt[Dot11].type == 0) and (pkt[Dot11].subtype == 8) :
        if pkt[Dot11].addr2 not in ap_list:
            ap_list.append(pkt[Dot11].addr2)

for i in range(len(a)):
    pkt = a[i]
    if (pkt.haslayer(Dot11WEP) and pkt.addr2 not in ap_list and pkt.addr1==pkt.addr3 and pkt[Dot11].FCfield==65L):
         pkt.show()
         raw_input()
         evil_packets.append(pkt)

print len(evil_packets)
