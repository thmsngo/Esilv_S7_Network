import sqlite3

conn = sqlite3.connect('logserver.db')

c = conn.cursor()


for row in c.execute('SELECT * FROM unauthorizedDns'):
    print(row)


conn.close()