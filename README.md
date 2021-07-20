# DC25

This git push is our final "after-talk" update.  On or before 14 August 2017, we will make a push to github.com accordingly.

As Jack64 and I are in different timezones, I don't know if he is planning on pushing OOBackdoor to his repository or our shared repoistory, thus you will see two links for OOBackdoor, check them both and one of them will work.

https://github.com/ICSec/airpwn-ng</br>
https://github.com/ICSec/pyDot11</br>

https://github.com/ICSec/OOBackdoor</br>
-or-</br>
https://github.com/Jack64/OOBackdoor

To those who came to our workshop, thank you so much.  This was our first time submitting to Defcon and each and everyone of you were interested, you asked questions, you made the class.  From both of us, Thank You.

While a requirements.txt would be highly appropriate, for this Proof of Concept to work with WPA2 CCMP, do as such:
- python2 -m pip install RESOURCEs/*.tar.gz
- python2 -m pip install RESOURCEs/scapy-2.3.1.tar.gz
- python2 -m pip install RESOURCEs/pyDot11-1.0.2.2.tar.gz

The given syntax for WPA2 CCMP usage is (single quotes are your friend...):
```
python2 ./airpwn-ng -i <injection mode NIC> -m <monitor mode NIC> --bssid '<BSSID>' --essid '<ESSID>' --wpa '<PSK>' --injection <payload>

i.e.
python2 ./airpwn-ng -i wlan1mon -m wlan1mon --bssid 'aa:bb:cc:dd:ee:ff' --essid 'ZerosAndOnes' --wpa 'SuperHardPassword' --injection payloads/wargames
```

--Jack64 and stryngs
