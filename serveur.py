import socket
import sqlite3


"""
def ip_creation(mac_adress):
    if(check(mac_adress)):
        return ip_selection()
    else:
        print("Access Denied")
 """
   
def ip_selection(mac_adress):
    ip_adress_list = SqlDHCP()
    for i in range(len(ip_adress_list)):
        if(ip_adress_list[i][1]==None):
            InsertMAC(mac_adress,ip_adress_list[i][0])
            return ip_adress_list[i]
    return "No adress available"    


def InsertMAC(mac_adress,ip):
    conn = sqlite3.connect('server.db')
    cur = conn.cursor()
    print("Connexion réussie à SQLite")
    sql = "UPDATE DHCP SET Mac_Adress=? WHERE IP_Adress=?"
    value = (mac_adress,ip)
    cur.execute(sql, value)
    conn.commit()
    print("Enregistrement mis à jour avec succès")
    cur.close()
    conn.close()
    print("Connexion SQLite est fermée")
    
def logs():
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * from Logs""")
        adressList = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()


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
    
    #DNS : Receive a domain name, and call the socket library to get the IP
    domain = clientsocket.recv(4096)
    ip_domain=socket.gethostbyname(domain.decode())
    clientsocket.send(bytes("The IP Adress of this domain name is "+ip_domain,"UTF-8"))

    #Closing socket
    clientsocket.close()
    serversocket.close()