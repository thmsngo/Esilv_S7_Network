from scapy.all import *
import sqlite3
import time

def mainSniff(p):

    if(p.dport == 53)or(p.sport == 53):

        if p.qr == 1 and p.ancount >= 1: 

            domainName = p.qd.qname #type : <class 'bytes'>
            domainName = domainName.decode() #type : <class 'str'>

            ip = p.an.rdata #type : <class 'str'>
            print("Nom de domaine : {} | IP : {}".format(domainName,ip))

    if(p.dport == 67)or(p.sport == 67):
        pass

    if(p.dport == 68)or(p.sport == 68):
        pass

    
sniff(prn=mainSniff,filter="port 53 or port 67 or port 68",store=0)