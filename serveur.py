import socket
import sqlite3
from datetime import date,datetime


"""
def ip_creation(mac_adress):
    if(check(mac_adress)):
        return ip_selection()
    else:
        print("Access Denied")
 """


#Choose the first free IP_Adress, and update it with the mac_adress
def ip_selection(mac_adress):
    ip_adress_list = SqlDHCP()
    for i in range(len(ip_adress_list)):
        if(ip_adress_list[i][1]==None):
            InsertLog(ip_adress_list[i],"DHCP")
            InsertMAC(mac_adress,ip_adress_list[i][0])
            return ip_adress_list[i]
    return "No adress available"    


#Update Database with the mac adress of the client
def InsertMAC(mac_adress,ip):
    conn = sqlite3.connect('server.db')
    cur = conn.cursor()
    sql = "UPDATE DHCP SET Mac_Adress=? WHERE IP_Adress=?"
    value = (mac_adress,ip)
    cur.execute(sql, value)
    conn.commit()
    print("Enregistrement mis à jour avec succès")
    cur.close()
    conn.close()
   
    
#Insert into database the request, the author of the request and datetime
#IP is the ip adress of the author, request can be "DHCP" or "DNS", depending
#on the request
def InsertLog(ip,request):
    try:
        conn = sqlite3.connect('server.db')
        cur = conn.cursor()
        sql = "INSERT INTO Logs(IP_Adress,Date,Time,Content) VALUES(?,?,?,?)"
        Date=date.today()
        Time=datetime.now().time()
        Content=request+" request by "+str(ip)+" at "+str(Date)+" "+str(Time)
        value = (str(ip),str(Date),str(Time),Content)
        cur.execute(sql, value)
        conn.commit()
        print("Log enregistré avec succès")
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

#Retrieve all the IP Adress and Mac Adress from the Database
def SqlDHCP():
    adressList=[]
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * from DHCP""")
        adressList = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return adressList


def check(mac_adress):
    None
     #SQL request 


def DisplayDatabase(db_file):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    with conn:
        cur.execute("SELECT * FROM DHCP")
        print(cur.fetchall())


if __name__ == '__main__':

    HOSTNAME = '127.0.0.1'
    PORT = 10998
    ip_adress = "127.0.0.1"

    #Connection & Accept the client
    serversocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP
    serversocket.bind((HOSTNAME,PORT))
    serversocket.listen()
    (clientsocket, address) = serversocket.accept() #Get the mac adress from client.py

    #Receive the Mac adress, check for IP adress and give it to client
    mac_adress = clientsocket.recv(4096) #recommended number in the doc
    print(mac_adress.decode())
    ip_adress=ip_selection(mac_adress.decode())
    clientsocket.send(bytes("Your IP Adress is "+ip_adress[0],"UTF-8"))
    
    #Confirmation of IP Adress
    confirmation = clientsocket.recv(4096)
    print(confirmation.decode())
    
    #Display the logs
    print(logs)
    
    #DNS : Receive a domain name, and call the socket library to get the IP
    domain = clientsocket.recv(4096)
    ip_domain=socket.gethostbyname(domain.decode())
    clientsocket.send(bytes("The IP Adress of this domain name is "+ip_domain,"UTF-8"))

    #Closing socket
    clientsocket.close()
    serversocket.close()