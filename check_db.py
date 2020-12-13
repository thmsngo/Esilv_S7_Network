import sqlite3
from sqlite3 import Error

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

if __name__ == '__main__':
    create_connection(r"server.db")
    DisplayDatabase(r"server.db")