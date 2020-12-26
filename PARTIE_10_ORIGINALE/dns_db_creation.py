import sqlite3

conn = sqlite3.connect('dns_db.db')

c = conn.cursor()

c.execute('''CREATE TABLE dns
(ip TEXT, domainName TEXT)''')

c.execute('''INSERT INTO dns
VALUES('128.77.88.23','monSite.com')''')
c.execute('''INSERT INTO dns
VALUES('11.23.33.21','fromage.fr')''')
conn.commit()

conn.close()