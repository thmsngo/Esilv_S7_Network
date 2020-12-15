import socket
import sqlite3
import time

"""
mac_address = "00-15-5D-B7-B1-48"
"""
#Get a random MAC address from database
def GetaMACaddress():
    mac_address=""
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT Mac_address FROM Macs ORDER BY random() LIMIT 1;""")
        mac_address = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to get a mac address from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return ''.join(mac_address[0])

if __name__ == '__main__':

    #Initialization
    HOSTNAME = '127.0.0.1'
    PORT = 10998
    mac_address = GetaMACaddress()
    print(mac_address)
    #mac_address = "00-15-5D-B7-B1-48"

    #Connection to server
    clientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP
    clientsocket.connect((HOSTNAME,PORT))

    #Sending an address mac and receiving an IP Address
    clientsocket.send(bytes(mac_address,"UTF-8")) 
    ip_address= clientsocket.recv(4096) 
    print(ip_address.decode())
    if(ip_address.decode()=="Server: There aren't any IP address available"):
        clientsocket.close()
    else:
        time.sleep(2) 
    
        #Confirmation to the server
        clientsocket.send(bytes("Client: Thanks for the IP address","UTF-8"))
    
        #Send a domain name and call the DNS SERVER to receive the IP
        domain=input("Type a domain name >")
        clientsocket.send(bytes(domain,"UTF-8")) 
        ip_domain= clientsocket.recv(4096)
        print(ip_domain.decode())
    
        #Respond to demand of display logs
        display_logs= clientsocket.recv(4096) 
        print(display_logs.decode())
        display_logs_respond=input()
        clientsocket.send(bytes(display_logs_respond,"UTF-8")) 
        
        #Sort the logs or not
        display_logs_type= clientsocket.recv(4096)
        print(display_logs_type.decode())
        display_logs_type_respond=input()
        clientsocket.send(bytes(display_logs_type_respond,"UTF-8")) 
        
        display_logs= clientsocket.recv(4096)
        print(display_logs.decode())
    
        #Closing socket
        clientsocket.close()


