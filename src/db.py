import sqlite3
import os 

path_migrare = "migrari.sql"



def get_connection(path):  # vrem rezultate de tip dict 
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")    
        return conn
    except sqlite3.Error as e:
        print(f"Eroare la conexiunea catre baza de date: {e}")
        return None
    

def db_init(path):
    conn = get_connection(path)
    with open(path_migrare, 'r') as f:
        cod = f.read()
    conn.executescript(cod)
    conn.commit()
    conn.close()
    print("Baza de date a fost initializata")
    