import socket
import sqlite3

'''
chr() : int to str

ord() : str to int

Binary and hex in python 

bin(12) = '0b1100'
int(bin(12),2) = 12

hex(18) = '0x18'
int(hex(18),16) = 24

Il faut encore convertir en bytes le str pour l'utiliser avec les sockets
bytes([12]) = b'\x0c' (Attention la fonction bytes() prend une liste d'int en argument)
bytes([12,132,2,31]) = b'\x0c\x84\x02\x1f'
'''

HOSTNAME = '127.0.0.1'
PORT = 53

serversocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #IPv4,UDP

serversocket.bind((HOSTNAME,PORT))

#serversocket.listen() operation not supported ???
#(clientsocket, address) = serversocket.accept() not supported, surrement parce que UDP
#t'as pas besoin d'une connection


def getDomainNameParts(data):

	data = data[12:]
	#Le header d'une query DNS fait 12 bytes

	charLength = True
	length = 0

	domainString = ''
	domainParts = []
	
	counter = 0
	
	for byte in data:
		
		if charLength:
			length = byte
			charLength = False
			
		else:
			domainString += chr(byte)
			counter += 1			
			
			if counter == length:
				domainParts.append(domainString)
				domainString = ''
				charLength = True
				counter = 0

			if byte == 0:
				break

	return(domainParts)

def domainToHex(domainParts):

	domainHex = b''

	for part in domainParts:
		length = len(part)
		domainHex += bytes([length])

		for char in part:
			domainHex += bytes([ord(char)])

	domainHex += b'\x00'

	return(domainHex)
	
def ipToHex(ip):

	ipHex = b''

	listIp = ip.split('.')

	for number in listIp:
		ipHex += bytes([int(number)])

	return ipHex		

def buildresponseHeader(data):

	#TransactionID
	TransactionID = data[0:2]

	#Flags
	'''
	QR = 1
	OPCODE = 0000
	AA = 1
	TC = 0
	RD = 0
	'''
	byte1 = '10000100'
	byte1 = int(byte1,2) #132
	byte1 = bytes([byte1]) #b'\x84'

	'''
	RA = 0
	Z = 000
	RCODE = 0000
	'''
	byte2 = '00000000'
	byte2 = int(byte2,2) #0
	byte2 = bytes([byte2]) #b'\x00'

	Flags = byte1+byte2 #b'\x84\x00'

	#QDCOUNT
	QDCOUNT = b'\x00\x01'

	#ANCOUNT
	ANCOUNT = b'\x00\x01'

	#number of name server resource records in the authority records section
	NSCOUNT = b'\x00\x00'

	#number of resource records in the additional records section
	ARCOUNT = b'\x00\x00'

	return TransactionID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

def buildresponseQuestion(data):

	#QNAME 
	domainNameParts = getDomainNameParts(data)
	domainHex = domainToHex(domainNameParts)
	QNAME = domainHex
	
	#type of the query
	QTYPE = b'\x00\x01'

	#the class of the query
	QCLASS = b'\x00\x01'

	return QNAME+QTYPE+QCLASS

def buildresponseBody(data,ip):
	
	
	#a domain name to which this resource record pertains. 
	NAME = b'\xc0\x0c'

	#one of the RR type codes
	TYPE = b'\x00\x01'

	#the class of the data in the RDATA field
	CLASS = b'\x00\x01'

	#TTL
	TTL = b'\x00\x00\x01\x26'

	#the length in octets of the RDATA field
	RDLENGTH = b'\x00\x04'

	#RDATA
	RDATA = ipToHex(ip)

	return NAME+TYPE+CLASS+TTL+RDLENGTH+RDATA


def buildresponse(data,ip):

	dnsheader = buildresponseHeader(data)
	dnsquestion = buildresponseQuestion(data)
	dnsbody = buildresponseBody(data,ip)

	return dnsheader+dnsquestion+dnsbody


conn = sqlite3.connect('dns_db.db')
c = conn.cursor()

while True:
	dataBytes,address = serversocket.recvfrom(512) #recommended in the rfc for up

	domainNameParts = getDomainNameParts(dataBytes)
	domainToHex(domainNameParts)
	domainName = '.'.join(domainNameParts)

	c.execute('SELECT ip FROM dns WHERE domainName == "{}"'.format(domainName))

	ip = c.fetchone() #tuple

	if ip!=None:
		ip = ip[0] #premier argument du tuple où est l'IP
	else:
		ip = '0.0.0.0'

	print("Nom de domaine : {} | IP : {}".format(domainName,ip))


	response = buildresponse(dataBytes,ip)

	serversocket.sendto(response,address)

conn.close()
serversocket.close()