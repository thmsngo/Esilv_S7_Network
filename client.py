import socket
import time

HOSTNAME = '127.0.0.1'
PORT = 10998
mac_adress = "00-15-5D-B7-B1-48"


clientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP

clientsocket.connect((HOSTNAME,PORT))


clientsocket.send(bytes(mac_adress,"UTF-8")) 
ip_adress= clientsocket.recv(4096)
print(ip_adress.decode()) 

time.sleep(1) 

clientsocket.send(bytes("Merci pour l'adresse ip : "+ ip_adress.decode(),"UTF-8"))

print(clientsocket.recv(4096).decode())

clientsocket.close()

clientsocket.close()


