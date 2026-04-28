from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

from src.vulnerabil.routes_util import router as auth_router
from src.db import db_init, get_connection
from src.models import *


secret_key = "cheiefoartesecreta"
alg = "HS256"


app = FastAPI(title="API vulnerabil", version="1.0vulnerabil")

app.include_router(auth_router)

@app.on_event("startup")
def start():
    db_init("data.db")
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
    

@app.get("/tickets")   # userul vede toate tichetele, nu doar pe ale lui
def create_ticket(user=Depends(get_current_user)):
    conn = get_connection("data.db")
    tickets = conn.execute("SELECT * FROM tickets").fetchall()
    return [dict(t) for t in tickets]

@app.post("/tickets")
def create_ticket(body: NewTicket, user=Depends(get_current_user)):  # nu sanitizam description
    conn = get_connection("data.db")
    conn.execute(
        """INSERT INTO tickets (title, description, severity, owner_id)
           VALUES (?, ?, ?, ?)""",
        (body.title, body.description, body.severity, user["sub"])
    )

    conn.commit()
    conn.close()
    return {"message": "Tichet creat"}

@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id):
    conn = get_connection()

    ticket = conn.execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    conn.close()

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return dict(ticket)



    
