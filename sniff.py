# -*- coding: utf-8 -*-
"""
Created on Tue Dec 15 18:47:08 2020

@author: M BUE
"""

#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

def showpckt(p):
    print(p.summary)
    print()
    
sniff(prn=showpckt,filter="port 53",store=0)


