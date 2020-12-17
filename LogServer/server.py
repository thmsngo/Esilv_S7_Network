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
def insertLog(macSrc,macDst,ipSrc,ipDst,portSrc,portDST,request):
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        sql="INSERT INTO logs(macSrc,macDst,ipSrc,ipDst,portSrc,portDST,date,time,request) VALUES(?,?,?,?,?,?,?,?,?)"
        day=date.today()
        time=datetime.datetime.now().time()
        values=(macSrc,macDst,ipSrc,ipDst,portSrc,portDST,str(day),str(time),request)
        cur.execute(sql,values)
        cur.commit()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()

# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass
            
def unauthorizedDNS(dns):
    valide=True
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        sql="SELECT * FROM unauthorizedDns WHERE ip=?"
        values=(dns,)
        cur.execute(sql,values)
        listUnauthorized=cur.fetchall()
        if(listUnauthorized.size()>0):
            valide=False
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
    return valide
def mainSniff(p):


    if(p.dport == 53)or(p.sport == 53):
        log = [p.src,p.dst]

        p = p[1] #on passe à la couche IP

        log.append(p.src)
        log.append(p.dst)
        log.append(p.sport)
        log.append(p.dport)
        log.append(str(date.today()))
        log.append(str(datetime.today().time()))
        print(log)

        domainName = p.qd.qname #type : <class 'bytes'>
        domainName = domainName.decode() #type : <class 'str'>

        typeRequest = p.qr

        if typeRequest == 1 :

            if p.ancount >= 1: 

                ip = p.an.rdata #type : <class 'str'>

                logRequest = "Answer DNS | Domain name : {} | IP : {}".format(domainName,ip)
                log.append(logRequest)
            else:
                logRequest = "Answer DNS | Domain name : {} | IP : Incorrect".format(domainName)
                log.append(logRequest)
        else:

            logRequest = "Query DNS | Domain name : {} ".format(domainName)
            log.append(logRequest)
        print(logRequest)

        print(log)
        #Checker si c'est autorisé 
        #On le met dans le fichier du jour
        day = date.today().strftime("%b-%d-%Y")
        file_name = "day_logs_" + day +".txt"
        with open(file_name, 'a') as output:
            output.write(logRequest + '\n')
        output.close()
        #On l'enregistre dans la database

    if(p.dport == 67)or(p.sport == 68):
        """
        c.execute('''CREATE TABLE logs
        (macSrc TEXT, macDst TEXT,
        ipSrc TEXT, ipDst TEXT, 
        portSrc INT, portDST INT, 
        date TEXT, time TEXT, 
        request TEXT)''')
        """ 
        macSrc = p.dst
        macDst = p.src
        p=p[1]
        ipSrc = p.src
        ipDst = p.dst
        portSrc = p.sport
        portDST = p.dport
        date = 
        time = 
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        request = f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}"
    
sniff(prn=mainSniff,filter="port 68 or port 67 or port 53",store=0)
#store=0 : Sinon on garde tout dans sniff() et au bout d'un moment ça va faire beaucoup