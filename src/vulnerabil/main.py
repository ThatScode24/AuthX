from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError

from src.vulnerabil.routes_util import router as auth_router
from src.db import db_init, get_connection, log_event, request_meta
from src.models import *


secret_key = "cheiefoartesecreta"
alg = "HS256"


app = FastAPI(title="API vulnerabil", version="1.0vulnerabil")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/version")
def version():
    return {"version": "v1", "label": "vulnerabil"}

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.on_event("startup")
def start():
    db_init("data_vulnerabil.db")
    print("Vulerabil pornit pe localhost:8000")

# auth middleware 

def get_current_user(request: Request):
    auth = request.headers.get("Authorization")

    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, secret_key, algorithms=[alg],
                             options={"verify_exp": False})  # nu verificam expirarea intentionat pt vulnerabilitate
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid")
    

@app.get("/tickets/search")  # vulnerabil: concatenam q direct in SQL → SQL injection
def search_tickets(q: str, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    sql = f"SELECT * FROM tickets WHERE title LIKE '%{q}%' OR description LIKE '%{q}%'"
    try:
        rows = conn.execute(sql).fetchall()
    except Exception as e:
        conn.close()
        log_event("data_vulnerabil.db", "TICKET_SEARCH", user_id=int(user["sub"]),
                  category="TICKET", ip_address=ip, user_agent=ua,
                  outcome="FAILURE", notes=f"q={q!r} err={e}")
        raise HTTPException(status_code=400, detail=f"SQL error: {e}")
    conn.close()

    log_event("data_vulnerabil.db", "TICKET_SEARCH", user_id=int(user["sub"]),
              category="TICKET", ip_address=ip, user_agent=ua,
              notes=f"vulnerabil SQLi; q={q!r}; rows={len(rows)}")
    return [dict(r) for r in rows]


@app.get("/tickets")   # userul vede toate tichetele, nu doar pe ale lui
def list_tickets(request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")
    tickets = conn.execute("SELECT * FROM tickets").fetchall()
    log_event("data_vulnerabil.db", "TICKET_LIST", user_id=int(user["sub"]),
              category="TICKET", ip_address=ip, user_agent=ua,
              notes=f"returned {len(tickets)} rows (vulnerabil: fara filtrare ownership)")
    return [dict(t) for t in tickets]

@app.post("/tickets")
def create_ticket(body: NewTicket, request: Request, user=Depends(get_current_user)):  # nu sanitizam description
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")
    cur = conn.execute(
        """INSERT INTO tickets (title, description, severity, created_by)
           VALUES (?, ?, ?, ?)""",
        (body.title, body.description, body.severity, user["sub"])
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_event("data_vulnerabil.db", "TICKET_CREATE", user_id=int(user["sub"]),
              ticket_id=new_id, category="TICKET",
              ip_address=ip, user_agent=ua, notes=body.title)

    return {"message": "Tichet creat"}

@app.patch("/tickets/{ticket_id}")  # vulnerabil: oricine poate edita orice tichet (IDOR + lipsa rol Manager)
def update_ticket(ticket_id: int, body: TicketPatch, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    ticket = conn.execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()

    if not ticket:
        conn.close()
        log_event("data_vulnerabil.db", "TICKET_UPDATE", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="ticket inexistent")
        raise HTTPException(status_code=404, detail="Ticket not found")

    # nu verificam nici owner-ul nici rolul (intentionat vulnerabil)
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        conn.close()
        raise HTTPException(status_code=400, detail="Nu ai trimis niciun camp")

    set_clause = ", ".join(f"{k} = ?" for k in fields.keys())
    values = list(fields.values()) + [ticket_id]
    conn.execute(
        f"UPDATE tickets SET {set_clause}, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
        values
    )
    conn.commit()
    conn.close()

    log_event("data_vulnerabil.db", "TICKET_UPDATE", user_id=int(user["sub"]),
              ticket_id=ticket_id, category="TICKET",
              ip_address=ip, user_agent=ua,
              notes=f"vulnerabil: fara ownership/role check; campuri={list(fields.keys())}")

    return {"message": "Tichet actualizat", "fields": list(fields.keys())}


@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    ticket = conn.execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    conn.close()

    if not ticket:
        log_event("data_vulnerabil.db", "TICKET_VIEW", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="ticket inexistent")
        raise HTTPException(status_code=404, detail="Ticket not found")

    log_event("data_vulnerabil.db", "TICKET_VIEW", user_id=int(user["sub"]),
              ticket_id=ticket_id, category="TICKET",
              ip_address=ip, user_agent=ua,
              notes="vulnerabil: fara verificare ownership")
    return dict(ticket)



    
