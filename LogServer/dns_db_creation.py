import sqlite3

conn = sqlite3.connect('logserver.db')

c = conn.cursor()

c.execute('''CREATE TABLE logs
(macSrc TEXT, macDst TEXT,
 ipSrc TEXT, ipDst TEXT, 
 portSrc INT, portDST INT, 
 date TEXT, time TEXT, 
 request TEXT)''')
 #IP du serveur DNS dans IP

c.execute('''INSERT INTO logs
VALUES('f4:6b:ef:6a:ad:c7','7c:67:a2:19:ec:e1','8.8.8.8','173.37.22.33',53,6678,'2020-12-16','14:45:37.410333','Rep blbablabla')''')
conn.commit()

conn.close()