from scapy.all import *
import sqlite3
import smtplib, ssl
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
def insertLog(log):
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        sql="INSERT INTO logs(macSrc,macDst,ipSrc,ipDst,portSrc,portDST,date,time,request) VALUES(?,?,?,?,?,?,?,?,?)"
        values=(log[0],log[1],log[2],log[3],log[4],log[5],log[6],log[7],log[8])
        cur.execute(sql,values)
        conn.commit()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
            
def unauthorizedDNS(dns):
    valide=True
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        sql="SELECT * FROM unauthorizedDns WHERE ip=?"
        values=(dns,)
        cur.execute(sql,values)
        listUnauthorized=cur.fetchall()
        if(len(listUnauthorized)>0):
            valide=False
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
    return valide

def unauthorizedDHCP(mac):
    valide=True
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        sql="SELECT * FROM unauthorizedMac WHERE mac=?"
        values=(mac,)
        cur.execute(sql,values)
        listUnauthorized=cur.fetchall()
        if(len(listUnauthorized)>0):
            valide=False
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
    return valide


def mail():
    portEmail = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "projetnetwork9@gmail.com"  # Enter your address
    receiver_email = "projetnetwork9@gmail.com"  # Enter receiver address
    message = """\
    Subject: DDOS ATTEMPT
    
    Server received a lot of request. 
    There is a high probability that a ddos is trying to shutdown the server."""
    
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, portEmail, context=context) as server:
        server.login(sender_email, "ProjetNetwork1!")
        server.sendmail(sender_email, receiver_email, message)
            

def mainSniff(p):


    if(p.dport == 53)or(p.sport == 53):

        log = []
        log.append(p.src)
        log.append(p.dst)

        p = p[1] #on passe à la couche IP

        log.append(p.src)
        log.append(p.dst)
        log.append(p.sport)
        log.append(p.dport)
        log.append(str(date.today()))
        log.append(str(datetime.today().time()))

        domainName = p.qd.qname #type : <class 'bytes'>
        domainName = domainName.decode() #type : <class 'str'>

        typeRequest = p.qr

        if typeRequest == 1 : #Answer

            if(unauthorizedDNS(str(p.src))):

                if p.ancount >= 1: #Si la réponse possède une une IP de réponse correcte

                    ip = p.an.rdata #type : <class 'str'>
                    logRequest = "Answer DNS | Domain name : {} | IP : {}".format(domainName,ip)
                    log.append(logRequest)
                else:
                    logRequest = "Answer DNS | Domain name : {} | IP : Incorrect".format(domainName)
                    log.append(logRequest)

            else:
                logRequest = "DNS IS BANNED"
                log.append(logRequest)
                with open("blacklist.txt", 'a') as output:
                    for prop in log:
                        output.write(str(prop) +" / ")
                    output.write("\n")
                    output.close()
             

        elif typeRequest == 0 : #Query

            if(unauthorizedDNS(str(p.dst))):
                logRequest = "Query DNS | Domain name : {} ".format(domainName)
                log.append(logRequest)
            else:
                logRequest = "DNS IS BANNED"
                log.append(logRequest)
                with open("blacklist.txt", 'a') as output:
                    for prop in log:
                        output.write(str(prop) +" / ")
                    output.write("\n")
                    output.close()

        day = str(date.today())
        file_name = "day_logs_" + day +".txt"
        logStr = ""
        for elt in log:
            logStr += str(elt)+" | "
        with open(file_name, 'a') as output:
            output.write(logStr + '\n')
        output.close()

        insertLog(log)
        print(log)

    if(p.dport == 67)or(p.sport == 68):

        macSrc = p.src
        macDst = p.dst
        p=p[1]
        ipSrc = p.src
        ipDst = p.dst
        portSrc = p.sport
        portDst = p.dport
        date_d = str(date.today())
        time_t = str(datetime.today().time())

        if p[3].options[0][1] == 1: #discover

            vendor_class_id = p[3].options[3][1].decode()
            request = ""
            if unauthorizedDHCP(macSrc):
                request = "Discover DHCP | Vendor class id {}".format(vendor_class_id)
            else:
                request="Discover DHCP | UNAUTHORIZED MAC {} DETECTED ON DHCP".format(macSrc)
                logs = [macSrc,macDst,ipSrc,ipDst,portSrc,portDst,date_d,time_t,request]
                with open("blacklist.txt", 'a') as output:
                    for prop in logs:
                        output.write(str(prop) +" / ")
                    output.write('\n')
                    output.close()

        elif p[3].options[0][1] == 3: #request

            vendor_class_id = p[3].options[5][1].decode()
            ip_p = p[3].options[2][1]
            request = ""
            if unauthorizedDHCP(macSrc):
                request = "Request DHCP | Vendor class id {} ({}) requested {}".format(vendor_class_id,macSrc,ip_p)
            else:
                request="Request DHCP | UNAUTHORIZED MAC {} DETECTED ON DHCP FROM {}".format(macSrc,vendor_class_id)
                logs = [macSrc,macDst,ipSrc,ipDst,portSrc,portDst,date_d,time_t,request]
                with open("blacklist.txt", 'a') as output:
                    for prop in logs:
                        output.write(str(prop) +" / ")
                    output.write('\n')
                    output.close()

        log = [macSrc,macDst,ipSrc,ipDst,portSrc,portDst,date_d,time_t,request]

        day = str(date.today())
        file_name = "day_logs_" + day +".txt"

        logStr = ""
        for elt in log:
            logStr += str(elt)+" | "

        with open(file_name, 'a') as output:
            output.write(logStr + '\n')
        output.close()

        insertLog(log)
        print(log)
    
sniff(prn=mainSniff,filter="port 68 or port 67 or port 53",store=0)
#store=0 : Sinon on garde tout dans sniff() et au bout d'un moment ça va faire beaucoup