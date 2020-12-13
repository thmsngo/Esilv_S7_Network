import socket
import sqlite3
from datetime import date,datetime
import pickle


"""
def ip_creation(mac_address):
    if(check(mac_address)):
        return ip_selection()
    else:
        print("Access Denied")
 """


#Choose the first free IP_Address, and update it with the mac_address
def ip_selection(mac_address):
    ip_address_list = SqlDHCP()
    for i in range(len(ip_address_list)):
        if(ip_address_list[i][1]==None):
            InsertMAC(mac_address,ip_address_list[i][0])
            #InsertLog(ip_address_list[i][0],"DHCP")
            return ip_address_list[i]
        else:
            return "No address available" 

#Update Database with the mac address of the client
def InsertMAC(mac_address,ip):
    conn = sqlite3.connect('server.db')
    cur = conn.cursor()
    sql = "UPDATE DHCP SET Mac_Address=? WHERE IP_Address=?"
    value = (mac_address,ip)
    cur.execute(sql, value)
    conn.commit()
    cur.close()
    conn.close()
   
#Insert into database the request, the author of the request and datetime
#IP is the ip address of the author, request can be "DHCP" or "DNS", depending
#on the request
def InsertLog(mac,ip_address,domain):
    try:
        conn = sqlite3.connect('server.db')
        cur = conn.cursor()
        sql = "INSERT INTO Logs(Mac_Address,IP_Used,Date,Time,Content) VALUES(?,?,?,?,?)"
        Date=date.today()
        Time=datetime.now().time()
        Content="Request by "+str(mac)+" with the IP "+ip_address[0]+" at "+str(Date)+" "+str(Time)+" for the website "+domain
        value = (str(mac),str(ip_address[0]),str(Date),str(Time),Content)
        cur.execute(sql, value)
        conn.commit()
        print("Log saved successfully")
        cur.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
  
#Retrieve all the logs from the database
def logs():
    logList=[]
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * from Logs""")
        logList = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return logList

#Retrieve all the IP Address and Mac Address from the Database
def SqlDHCP():
    addressList=[]
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * from DHCP""")
        addressList = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return addressList

#Notify if the domain asked is in the list of unauthorized DNS
def CheckDomainValidity(domain,ip_domain):
    authorized=True
    DNS_list=[]
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * from DNS""")
        DNS_list = cursor.fetchall()
        cursor.close()

        for i in range(len(DNS_list)):            
            if(domain==DNS_list[i][0] or ip_domain==DNS_list[i][1] ):
                authorized=False

    except sqlite3.Error as error:
        print("Failed to check domain validity from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return authorized
 
def AskDisplayLogs():
    display=False
    clientsocket.send(bytes("Server: Do you want to display logs ? y or n","UTF-8"))
    confirmation = clientsocket.recv(4096)
    if(confirmation.decode()=="y" or confirmation.decode()=="Y" or confirmation.decode()=="yes"):
        data=str(logs())
        clientsocket.send(bytes(data,"UTF-8"))
    else:
        clientsocket.send(bytes("Server: Okay I don't display logs","UTF-8"))


if __name__ == '__main__':

    HOSTNAME = '127.0.0.1'
    PORT = 10998
    ip_address = "127.0.0.1"

    #Connection & Accept the client
    serversocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP
    serversocket.bind((HOSTNAME,PORT))
    serversocket.listen()
    (clientsocket, address) = serversocket.accept() #Get the mac address from client.py

    #Receive the Mac address, check for IP address and give it to client
    mac_address = clientsocket.recv(4096) #recommended number in the doc
    print(mac_address.decode())
    ip_address=ip_selection(mac_address.decode())

    if (ip_address=="No address available"):
        clientsocket.send(bytes("Server: There aren't any IP address available","UTF-8"))
    else:
        clientsocket.send(bytes("Server: Your IP address is "+ip_address[0],"UTF-8"))
    
    #Confirmation of IP Address
    confirmation = clientsocket.recv(4096)
    print(confirmation.decode())
    
    #DNS : Receive a domain name, and call the socket library to get the IP
    domain = clientsocket.recv(4096)
    ip_domain=socket.gethostbyname(domain.decode())
    
    if(CheckDomainValidity(domain.decode(),ip_domain)):
        clientsocket.send(bytes("The IP address of this domain name is "+ip_domain,"UTF-8"))
    else:
        clientsocket.send(bytes(ip_domain + " is in the list of unauthorized domaine name","UTF-8"))
    
    #Retrieval server's logs
    InsertLog(mac_address.decode(),ip_address,domain.decode())
    
    #Ask client to display logs
    AskDisplayLogs()

    #Closing socket
    serversocket.close()
    clientsocket.close()