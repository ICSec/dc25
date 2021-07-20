#!/usr/bin/python

from scapy.all import *
import requests,sys,json

aps=set([])

#make sure user inputs a file
if (len(sys.argv)!=2):
    print "Usage: ./geolocate-pcap.py <pcap>"
    exit()

pkts = rdpcap(sys.argv[1])
for pkt in pkts:
    #filter for 802.11 beacons
    if (pkt.haslayer(Dot11) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8):
        bssid=pkt[Dot11].addr2
        essid=pkt[Dot11Elt].info
        #due to the difference between different wifi drivers, rssi value is hardcoded
        #to improve compatibility of this script (at the expense of a little accuracy)
        rssi=-50
        obj = (essid,bssid,rssi)
        aps.add(obj)

if (len(aps)==0):
    print "[-] No 802.11 beacon packets detected, exiting."
    exit()

API_URL="https://maps.googleapis.com/maps/api/browserlocation/json?browser=firefox&sensor=true&"

for essid,bssid,rssi in aps:
    API_URL+="wifi=mac:"+bssid+"|ssid:"+essid+"|ss="+str(rssi)+"&"
API_URL=API_URL[:-1]

response=json.loads(requests.get(API_URL).content)

if (response["accuracy"]==346292):
    print "[-] Not enough information to accurately pinpoint location."
    exit()

print "Accuracy:",response["accuracy"],"m"
print "Latitude:",response["location"]["lat"]
print "Longitude:",response["location"]["lng"]
print "Map URL: "+"https://maps.google.com/?q="+str(response["location"]["lat"])+","+str(response["location"]["lng"])
