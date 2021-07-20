from scapy.all import *
from base64 import b64decode

pkts = rdpcap('../PCAPs/OOBackdoor/lvl0exfil.pcap')
for pkt in pkts:
    if (pkt.haslayer(Dot11) and pkt.haslayer(Dot11Elt)):
        if (pkt[Dot11Elt].ID==0 and len(pkt[Dot11Elt:2].info)>8):
            try:
                print "[Client]\n",b64decode(pkt[Dot11Elt:2].info),"\n---------"
            except:
                pass
        if (len(pkt[Dot11Elt].info)>32):
            print "[Server]\n",b64decode(pkt[Dot11Elt].info),"\n---------"
