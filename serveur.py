import socket
import sqlite3


HOSTNAME = '127.0.0.1'
PORT = 10998
ip_adress = "127.0.0.1"


serversocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP

serversocket.bind((HOSTNAME,PORT))

serversocket.listen()

(clientsocket, address) = serversocket.accept()

mac_adress = clientsocket.recv(4096) #recommended number in the doc
print(mac_adress.decode())
ip_adress=ip_selection(mac_adress.decode())
clientsocket.send(bytes(ip_adress,"UTF-8"))


confirmation = clientsocket.recv(4096)
clientsocket.send(bytes("tqt fréro","UTF-8"))

print(confirmation.decode())

clientsocket.close()
serversocket.close()


"""
def ip_creation(mac_adress):
    if(check(mac_adress)):
        return ip_selection()
    else:
        print("Access Denied")
 """
   
def ip_selection(mac_adress):
    ip_adress_list = SqlDHCP()
    for i in range(len(ip_adress_list),2):
        if(ip_adress_list[i+1]==None):
            InsertMAC(ip_adress_list[i+1],ip_adress_list[i])
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