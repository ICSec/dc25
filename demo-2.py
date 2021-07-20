#!/usr/bin/python

"""
This demo will do two things:
    - Teach the user how to sniff and hunt
    
    - Possibly recover stolen gear
    
    - Goal:
        - Use lfilter to only use HP within prn
        - Use prn to parse
    
    - Bonus:
        - RSSI
"""

from scapy.all import *

## Section 1
##############################################################################

## Notate the environment
tgtMac = 'aa:bb:cc:dd:ee:ff'
iFace = 'wlan1mon'

def macFinder(myMac):
    """Listen for and notate when myMac is found"""
    def snarf(packet):
        if packet[Dot11].addr1 == myMac or\
           packet[Dot11].addr2 == myMac or\
           packet[Dot11].addr3 == myMac or\
           packet[Dot11].addr3 == myMac:
            return True
        else:
            return
    return snarf


def macFound(packet):
    pType = symString(packet[Dot11], packet[Dot11].type, 'type')
    direcFlag = symString(packet[Dot11], packet[Dot11].FCfield, 'FCfield')
    print '%s Found! - %s - %s' % (tgtMac, pType, direcFlag)
    

def symString(packet, pField, fString):
    """Shows the symblic string for a given field

    Where p is UDP(), and you want p.dport symbolically:
        symString(p, p.dport, 'dport')
    
    Where p is UDP()/DNS(), and you want p[DNS].opcode symbolically:
        symString(p[DNS], p[DNS].opcode, 'opcode')
    """
    return packet.get_field(fString).i2repr(packet, pField)
##############################################################################



## Section 2
##############################################################################

pFilter = macFinder(tgtMac)
sniff(iface = iFace, prn = macFound, lfilter = pFilter)
##############################################################################



## Section 3
##############################################################################

## 2x == Show me the signal strength
## 4x == Show me the frequency
## 8x == Show me the channel
