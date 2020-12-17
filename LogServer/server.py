from scapy.all import *
import sqlite3
from datetime import date,datetime
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

        domainName = p.qd.qname #type : <class 'bytes'>
        domainName = domainName.decode() #type : <class 'str'>

        typeRequest = p.qr

        if typeRequest == 1 :

            if p.ancount >= 1: 

                ip = p.an.rdata #type : <class 'str'>

                logRequest = "Answer DNS | Domain name : {} | IP : {}".format(domainName,ip)

            else:
                logRequest = "Answer DNS | Domain name : {} | IP : Incorrect".format(domainName)

        else:

            logRequest = "Query DNS | Domain name : {} ".format(domainName)

        print(logRequest)

        #Checker si c'est autorisé 
        #On le met dans le fichier du jour
        day = date.today().strftime("%b-%d-%Y")
        file_name = "day_logs_" + day +".txt"
        with open(file_name, 'a') as output:
            output.write(logRequest + '\n')
        output.close()
        #On l'enregistre dans la database

    if(p.dport == 67)or(p.sport == 67):
        pass

    if(p.dport == 68)or(p.sport == 68):
        pass

    
sniff(prn=mainSniff,filter="port 68 or port 67 or port 53",store=0)
#store=0 : Sinon on garde tout dans sniff() et au bout d'un moment ça va faire beaucoup