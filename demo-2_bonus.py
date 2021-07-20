## Pop to GUI
## Notate bytes
## Remember 0 index
wireshark(packet)

## Count out bytes accordingly
notDecoded = hexstr(str(packet.notdecoded), onlyhex=1).split(' ')




## Signal strength
fByte = notDecoded[x]
sig = -(256 - int(fByte, 16))


## Frequency
"""
As an example, 2.447 GHz will be used.
        
Bytewise 2447 is represented as 0x8f09.  Due to the way the IEEE deals
with certain aspects of 802.11, we have to Little Endian this,
thus 0x098f when converted to Decimal becomes 2447.
"""
lByte = notDecoded[y]
fByte = notDecoded[x]
fFreq = int(lByte + fByte, 16)


## Channel
## 5MHz spread
chanDict = {2412: '1', 2417: '2', 2422: '3', 2427: '4', 2432: '5', 2437: '6', 2442: '7', 2447: '8', 2452: '9', 2457: '10', 2462: '11', 2467: '12', 2472: '13', 2484: '14'}
ourChan = chanDict.get(fFreq)
