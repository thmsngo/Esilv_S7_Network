from scapy.all import *
import sqlite3
import datetime

'''
Pour utiliser datetime :

datetime.datetime.now()
datetime.datetime(2020, 12, 16, 14, 46, 19, 443506)

datetime.datetime.now().time()
datetime.time(14, 46, 32, 566475)

Convert to string: 
str(datetime.datetime.now().time())
'14:45:37.410333'
'''

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
#store=0 : Sinon on garde tout dans sniff() et au bout d'un moment ça va faire beaucoup