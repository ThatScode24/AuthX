from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from jose import jwt, JWTError, ExpiredSignatureError

from src.db import db_init, get_connection, log_event, request_meta
from src.models import NewTicket, TicketPatch
from src.securizat.routes_util import (
    router as auth_router, limiter,
    SECRET_KEY, ALG, DB_PATH,
)


app = FastAPI(title="API securizat", version="2.0securizat")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# restrangem corsul
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/version")
def version():
    return {"version": "v2", "label": "securizat"}


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.on_event("startup")
def start():
    db_init(DB_PATH)
    print(f"Securizat pornit cu db {DB_PATH}")

# aici avem middleware

def get_current_user(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")

    token = auth.split(" ", 1)[1]
    try:
        # semnatura si expirarea devin obligatorii pentru versiunea aceata
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALG])
    except ExpiredSignatureError:
        raise HTTPException(401, "Token expirat")
    except JWTError:
        raise HTTPException(401, "Token invalid")

    # verifica ca sesiunea nu a fost invalidata cu logout sau altele
    conn = get_connection(DB_PATH)
    sess = conn.execute(
        "SELECT is_invalidated FROM user_sessions WHERE session_token=?", (token,)
    ).fetchone()
    conn.close()
    if not sess or sess["is_invalidated"]:
        raise HTTPException(401, "Sesiune invalidata")

    return payload


def require_manager(user=Depends(get_current_user)):
    if user.get("role") != "MANAGER":
        raise HTTPException(403, "Permisiuni insuficiente (necesita rol MANAGER)")
    return user



# aici aem tichetele

@app.get("/tickets/search")
def search_tickets(q: str, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    pattern = f"%{q}%"
    conn = get_connection(DB_PATH)
    if user.get("role") == "MANAGER":
        rows = conn.execute(
            "SELECT * FROM tickets WHERE title LIKE ? OR description LIKE ?",
            (pattern, pattern)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM tickets
               WHERE (title LIKE ? OR description LIKE ?) AND created_by=?""",
            (pattern, pattern, int(user["sub"]))
        ).fetchall()
    conn.close()
    log_event(DB_PATH, "TICKET_SEARCH", user_id=int(user["sub"]),
              category="TICKET", ip_address=ip, user_agent=ua,
              notes=f"q={q!r}, role={user['role']}, rows={len(rows)}")
    return [dict(r) for r in rows]


@app.get("/tickets")
def list_tickets(request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)
    if user.get("role") == "MANAGER":
        tickets = conn.execute("SELECT * FROM tickets").fetchall()
    else:
        tickets = conn.execute(
            "SELECT * FROM tickets WHERE created_by=?", (int(user["sub"]),)
        ).fetchall()
    conn.close()
    log_event(DB_PATH, "TICKET_LIST", user_id=int(user["sub"]),
              category="TICKET", ip_address=ip, user_agent=ua,
              notes=f"role={user['role']}, returned={len(tickets)}")
    return [dict(t) for t in tickets]


@app.post("/tickets")
def create_ticket(body: NewTicket, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)
    cur = conn.execute(
        """INSERT INTO tickets (title, description, severity, created_by)
           VALUES (?, ?, ?, ?)""",
        (body.title, body.description, body.severity, int(user["sub"]))
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    log_event(DB_PATH, "TICKET_CREATE", user_id=int(user["sub"]),
              ticket_id=new_id, category="TICKET",
              ip_address=ip, user_agent=ua, notes=body.title)
    return {"message": "Tichet creat"}


@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, request: Request, user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)
    ticket = conn.execute(
        "SELECT * FROM tickets WHERE id=?", (ticket_id,)
    ).fetchone()
    if not ticket:
        conn.close()
        log_event(DB_PATH, "TICKET_VIEW", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="ticket inexistent")
        raise HTTPException(404, "Ticket not found")

    if user.get("role") != "MANAGER" and ticket["created_by"] != int(user["sub"]):
        conn.close()
        log_event(DB_PATH, "TICKET_VIEW", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="ownership denied")
        raise HTTPException(403, "Permisiuni insuficiente")

    conn.close()
    log_event(DB_PATH, "TICKET_VIEW", user_id=int(user["sub"]),
              ticket_id=ticket_id, category="TICKET",
              ip_address=ip, user_agent=ua)
    return dict(ticket)


@app.patch("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, body: TicketPatch, request: Request,
                  user=Depends(get_current_user)):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)

    ticket = conn.execute(
        "SELECT * FROM tickets WHERE id=?", (ticket_id,)
    ).fetchone()
    if not ticket:
        conn.close()
        raise HTTPException(404, "Ticket not found")

    is_manager = user.get("role") == "MANAGER"
    is_owner = ticket["created_by"] == int(user["sub"])

    if not is_manager and not is_owner:
        conn.close()
        log_event(DB_PATH, "TICKET_UPDATE", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="ownership denied")
        raise HTTPException(403, "Permisiuni insuficiente")

    fields = body.model_dump(exclude_unset=True)
    if not fields:
        conn.close()
        raise HTTPException(400, "Nu ai trimis niciun camp")

    if "status" in fields and not is_manager:
        conn.close()
        log_event(DB_PATH, "TICKET_UPDATE", user_id=int(user["sub"]),
                  ticket_id=ticket_id, category="TICKET",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="status change requires MANAGER role")
        raise HTTPException(403, "Doar MANAGER poate schimba statusul")

    # whitelist
    allowed = {"title", "description", "severity", "status"}
    fields = {k: v for k, v in fields.items() if k in allowed}

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [ticket_id]
    conn.execute(
        f"UPDATE tickets SET {set_clause}, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
        values
    )
    conn.commit()
    conn.close()

    log_event(DB_PATH, "TICKET_UPDATE", user_id=int(user["sub"]),
              ticket_id=ticket_id, category="TICKET",
              ip_address=ip, user_agent=ua,
              notes=f"campuri={list(fields.keys())}")
    return {"message": "Tichet actualizat", "fields": list(fields.keys())}
