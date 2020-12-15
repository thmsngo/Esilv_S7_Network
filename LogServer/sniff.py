from scapy.all import *
from scapy.layers.dns import DNSRR,DNS,DNSQR

def showpckt(packet):
    print(packet.summary)
    print()
    
sniff(prn=showpckt,filter="port 53",store=0)
