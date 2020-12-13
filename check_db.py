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

def GetaMACaddress():
    mac_adress=""
    try:
        sqliteConnection = sqlite3.connect('server.db')
        cursor = sqliteConnection.cursor()
        cursor.execute("""SELECT * FROM Macs ORDER BY random() LIMIT 1;""")
        mac_adress = cursor.fetchall()
        cursor.close()
    except sqlite3.Error as error:
        print("Failed to get a mac address from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
    return ''.join(mac_adress[0])

if __name__ == '__main__':
    """
    create_connection(r"server.db")
    DisplayDatabase(r"server.db")

    mac_adress = GetaMACaddress()
    print(type(mac_adress))
    print(mac_adress)
    """
    Date=date.today()
    time=datetime.now().time()
    print(Date)
    print(time)
