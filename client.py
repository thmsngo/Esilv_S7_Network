import socket
import time

HOSTNAME = '127.0.0.1'
PORT = 10998
mac_adress = "00-15-5D-B7-B1-48"


clientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #IPv4,TCP
clientsocket.connect((HOSTNAME,PORT))

#Sending an adress mac and receiving an IP Adress
clientsocket.send(bytes(mac_adress,"UTF-8")) 
ip_adress= clientsocket.recv(4096) 
print(ip_adress.decode())
time.sleep(2) 

#Confirmation to the server
clientsocket.send(bytes("Merci pour l'adresse ip "+ ip_adress.decode(),"UTF-8"))

#Send a domain name and call the DNS SERVER to receive the IP
domain=input("Type a domain name >")
clientsocket.send(bytes(domain,"UTF-8")) 
ip_domain= clientsocket.recv(4096)
print(ip_domain.decode())

#Closing socket
clientsocket.close()


