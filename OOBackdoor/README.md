# OOBackdoor

This repository contains scapy code that creates an out-of-band communication channel using 802.11 Data packets. It was inspired by <a href="https://www.trustwave.com/Resources/SpiderLabs-Blog/Smuggler---An-interactive-802-11-wireless-shell-without-the-need-for-authentication-or-association/">Trustwave's Project Smuggler</a>.
While they used Beacons and Probe Responses to send data between a client and server, the approach taken in OOBackdoor is to use actual 802.11 Data packets.

The goal is to mimmick 802.11 encrypted communications between an AP and a station, taking advantage of the fact that these frames are usually encrypted and often carry large payloads to hide among the background noise.

Other features include:
    * AES-CBC encryption
    * TOTP-based mac address hopping
    * ACK-based communications to prevent lost frames


