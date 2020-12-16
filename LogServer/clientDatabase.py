#Un truc dans le genre

import sqlite3

conn = sqlite3.connect('logserver.db')

c = conn.cursor()


def logsDuJour(Date):
    pass

#commandeSql = input("Entrez votre commande SQL")


c.execute("SELECT * FROM logs")

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
'''

'''
OUTPUT :
('128.77.88.23', 'monSite.com')
('11.23.33.21', 'fromage.fr')
'''