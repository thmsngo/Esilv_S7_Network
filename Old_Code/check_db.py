import sqlite3
from sqlite3 import Error
from datetime import date,datetime
from time import gmtime, strftime

def create_connection(db_file):
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print("Connexion réussie à SQLite")
        print(sqlite3.version)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()

def DisplayDatabase(db_file):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    with conn:
        cur.execute("SELECT * FROM DHCP")
        print(cur.fetchall())
#Get a random MAC address from database
def GetaMACaddress():
    mac_address=""
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * FROM Macs ORDER BY random() LIMIT 1;""")
        mac_address = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to get a mac address from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return ''.join(mac_address[0])

def CheckMAC(mac_address):
    validity = True
    conn = sqlite3.connect('server.db')
    cur = conn.cursor()
    sql = "SELECT Unauthorized_Mac_Address FROM Macs WHERE Unauthorized_Mac_Address LIKE '?';"
    cur.execute(sql, mac_address)
    if(cur.fetchall()==mac_address):
        validity = False
    conn.commit()
    cur.close()
    conn.close()
    return validity

if __name__ == '__main__':
    """
    create_connection(r"server.db")
    DisplayDatabase(r"server.db")
    """
    mac_address="00:00:0A:BB:28:FC"
    validity = True

    conn = sqlite3.connect('server.db')
    cur = conn.cursor()
    sql = "SELECT Unauthorized_Mac_Address FROM Macs WHERE Unauthorized_Mac_Address LIKE '?';"
    value=(str(mac_address))
    cur.execute(sql,value)
    if(''.join(cur.fetchall()[0])==mac_address):
        validity = False
    conn.commit()
    cur.close()
    conn.close()
    print(validity)

