'''
Comment accéder à la base de données
'''

import sqlite3

conn = sqlite3.connect('dns_db.db')

c = conn.cursor()

c.execute('SELECT ip FROM dns WHERE domainName = "google.com"')

n = c.fetchone()

if n!=None:
    print(n[0])

'''
OUTPUT :
[('128.77.88.23', 'monSite.com'), ('11.23.33.21', 'fromage.fr')]
'''


'''
for row in c.execute('SELECT * FROM dns'):
    print(row)


OUTPUT :
('128.77.88.23', 'monSite.com')
('11.23.33.21', 'fromage.fr')
'''