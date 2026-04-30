import sqlite3
import os

path_migrare = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrari.sql")



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


def log_event(path, event_type, *, user_id=None, ticket_id=None, category=None,
              target_id=None, ip_address=None, user_agent=None,
              outcome="SUCCESS", notes=None):
    conn = get_connection(path)
    conn.execute(
        """INSERT INTO audit_logs
           (user_id, ticket_id, event_type, category, target_id,
            ip_address, user_agent, outcome, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, ticket_id, event_type, category, target_id,
         ip_address, user_agent, outcome, notes)
    )
    conn.commit()
    conn.close()


def request_meta(request):
    ip = request.client.host if request and request.client else None
    ua = request.headers.get("user-agent") if request else None
    return ip, ua
    