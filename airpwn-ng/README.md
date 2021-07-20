The home of the new and improved version of airpwn... airpwn-ng
==============================================================
<hr>

Overview
---

* We force the target's browser to do what we want
	* Most tools of this type simply listen to what a browser does, and if they get lucky, they get the cookie.
	* What if the user isn't browsing the vulnerable site at the point in time which you are sniffing?
	* Wait, you say I can't force your browser to do something?  I sure can if you have cookies stored...
* Demo video: https://www.youtube.com/watch?v=hiyaUZh-UiU
* Find us on IRC (Freenode) at ##ha

Features
---

- Inject to all visible clients (a.k.a Broadcast Mode)
- Inject on both open networks and WEP/WPA protected networks
- Targeted injection with -t MAC:ADDRESS [MAC:ADDRESS]
- Gather all visible cookies (Broadcast Mode)
- Gather cookies for specific websites (--websites websites_list.txt)
	- In this scenario, airpwn-ng will auto-generate invisible iframes for injection that trigger the request for each website in websites_list.txt
	- [BETA] Can be used with --covert flag that attempts to inject a big iframe with the real requested website along with the generated invisible iframes. If successful, the victim should get no indication of compromise. This is still beta and doesn't work with all websites.
	- [BETA] Airpwn-ng API so you can make your own custom attacks. Examples: https://github.com/ICSec/airpwn-ng/blob/master/work-in-progress/api-examples/

How do we do it?
---
* We inject packets into a pre-existing TCP stream
    * For a more detailed and in-depth explanation as to how this occurs, read the original documentation for airpwn:
        * http://airpwn.sourceforge.net/Documentation.html


That's cool...  So what can we do with it?
---
- Find a website which uses cookies without the SECURE flag set
- Inject lots of wonderful images just like the original airpwn
- All sorts of fun...

Prerequisites:
---
airpwn-ng was built around scapy2.3.3 from PyPI.  Support and/or advice about airpwn-ng requires the user have this version on their system.  For your convience, a local copy of scapy has been included in RESOURCEs/.  If you don't have scapy, or have a different version of scapy on your system, then feel free to use the locally included .tgz.

During testing it was found there are some conflicts using scapy-2.3.3. So we have provided the older 2.2 version. For now, until those issues are worked out, please use the 2.2 version.

airpwn-ng and pyDot11 are currently undergoing a merge.  As both projects wish to support PyPy, certain requirements must be dealt with prior to this merge.  After the merge, these requirements will still be there, but they won't specifically revolve around the solution currently baked in to get airpwn-ng up and running with pyDot11.

Initial testing shows that PyPy slows down some aspects and speeds up other aspects of airpwn-ng and pyDot11.  It is not recommended to attempt airpwn-ng usage with PyPy at this time, but the option is still available if you wish.

Whether or not you wish to use PyPy, you must choose one of the following methods to get airpwn-ng up and running:

#### Non PyPy usage:
If you have scapy-2.2.0 from pyDot11 installed and available in your Python sys.path, you may disregard this step:
````bash
## From the airpwn-ng folder run the following
#pip install RESOURCEs/scapy-2.3.3.tgz
pip install RESOURCEs/scapy_2.2.0.orig.tar.gz

    ## OR ##

#tar zxf RESOURCEs/scapy-2.3.3.tgz
#mv scapy-2.3.3/scapy/ .
#rm -rf scapy-2.3.3/
tar zxf RESOURCEs/scapy_2.2.0.orig.tar.gz
mv scapy-2.2.0/scapy/ .
rm -rf scapy-2.2.0/
````
If you already have pyDot11 installed to your system and available in your Python sys.path, you may disregard this step:
````bash
## From the airpwn-ng folder run the following
pip install RESOURCEs/pyDot11-0.8.6.tar.gz
````
These other requirements can be met by using pip and the PyPI repository, or directly installing as such:
````bash
## From the airpwn-ng folder run the following
pip install RESOURCEs/pbkdf2-1.3.tar.gz -t _PYPY
pip install RESOURCEs/rc4-0.1.tar.gz -t _PYPY
pip install RESOURCEs/pycryptodomex-3.4.5.tar.gz
````

#### PyPy usage:
While using something such as virtualenv would achieve the desired outcome, the logic for avoiding the need has been baked into airpwn-ng by modifying sys.path and uing _PYPY as the parent folder for the PyPy modules.  Of the modules needed, pycryptodomex requires compilation by pypy itself.  Every other module can simply be installed to the _PYPY folder.  Directions are as such:
````bash
## From the airpwn-ng folder run the folder
pip install RESOURCEs/pyDot11-0.8.6.tar.gz -t _PYPY
pip install RESOURCEs/pbkdf2-1.3.tar.gz -t _PYPY
pip install RESOURCEs/rc4-0.1.tar.gz -t _PYPY
#pip install RESOURCEs/scapy-2.3.3.tgz -t _PYPY
pip install RESOURCEs/scapy_2.2.0.orig.tar.gz -t _PYPY
tar zxf RESOURCEs/pycryptodomex-3.4.5.tar.gz -C _PYPY
cd _PYPY/pycryptodomex-3.4.5/ && pypy setup.py build && mv build/lib*/Cryptodome ../ && cd ../../ && rm -rf _PYPY/pycryptodomex-3.4.5/
````


What else do we need to get started?
---
* Aircrack-ng:
  * http://www.aircrack-ng.org/

# How do we use airpwn-ng?
The WPA2 CCMP module for airpwn-ng is in the process of a revamp.  Somewhere between DC25 and today, things broke.  Time is limited in life and until now there has not been the time to debug what went wrong.  airpwn-ng can now once again decrypt, encrypt and inject on the fly for WPA2 CCMP using only 1 NIC.  It has been many years since these core modules were reviewed and will take time to catch this version of the codebase up to where airpwn-ng is today.

For now the easiest way to handle this is to keep the main repo on github for airpwn-ng useful for its current capabilities of Open and WEP, as is with Python3.  This iteration of airpwn-ng is being debugged using the Python 2.7.18 environment.  airpwn-ng was written at a time when scapy had not yet merged with Python 3x.  diff will surely be fun in this regard...

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
