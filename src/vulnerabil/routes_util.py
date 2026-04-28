from src.models import *
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, HTTPException
from jose import jwt 
from src.db import get_connection
import hashlib


secret_key = "cheiefoartesecreta"
alg = "HS256"


router = APIRouter(prefix="/auth", tags=["auth|vulnerabil"])

# cateva functii ajutatoare

def weak_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # un hash de acest tip este atacabil cu rainbow tables 


def create_weak_token(user_id, email, role):
    payload = {
        "sub": str(user_id),   # notam absenta lui exp, o facem intentionat vulnerabila la replay attacks
        "email": email,
        "role": role
    }
    return jwt.encode(payload, secret_key, algorithm=alg)

# rute

# nu avem nici blocare de cont nici rate limiting, nu avem token cu expirare, si avem mesae diferite pentru email inexistent si parola gresita
@router.post("/login", response_model=AuthTokenResponse)
def login(body: LoginReq, request: Request):
    conn  = get_connection("data.db")
    user = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Utilizator inexistent")
    
    password_hash = weak_password_hash(body.password)

    if user["password_hash"] != password_hash:
        conn.close()
        raise HTTPException(status_code=401, detail="Parola incorecta")
    
    tok = create_weak_token(user["id"], user["email"], user["role"])

    conn.execute(
        """INSERT INTO user_sessions (user_id, session_token, expires_at)
           VALUES (?, ?, datetime('now', '+100 years'))""",
        (user["id"], tok)
    )
    conn.commit()
    conn.close()

    return {"access_token": tok, "token_type": "bearer"}

# notam aici ca logout nu invalideaza tokenul, el va putea fi reutilizat  
@router.post("/logout", response_model=ApiResp)
def logout(request: Request):
    return { "message": ' Logged out'}


@router.post("/register", response_model=ApiResp) # nu verificam complexitatea paroleisi stocam parola ca md fara salt
def register(body: RegisterReq):
    conn = get_connection("data.db")

    exista_deja = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()

    if exista_deja:
        raise HTTPException(status_code=400, detail="Email deja folosit")
    
    hash_parola = weak_password_hash(body.password)

    conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'USER')",
        (body.email, hash_parola)
    )
    conn.commit()
    conn.close()

    return {"message": "User registered successfully"}



@router.post("/forgot-password", response_model=ApiResp)  # aici expunem existenta sau nu a emailului, iar tokenul este predicatable (timestamp)
def parola_uitata(body: ForgotPasswordReq):
    conn = get_connection("data.db")

    user = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="Email inexistent")

    reset_token = str(int(time.time()))  # predictable

    # facem token sa expire in 30 de zile, ceea ce e mult prea mult + trimitem direct tokenul in raspuns, trebia pe mail in mod normal

    conn.execute(
        """INSERT INTO password_reset_tokens (user_id, reset_token, expires_at)
           VALUES (?, ?, datetime('now', '+30 days'))""",
        (user["id"], reset_token)
    )
    conn.commit()
    conn.close()

    return {"message": f"Password reset token: {reset_token}"}

@router.post("/reset-password", response_model=ApiResp)  # token care expira dar e reutilizabil,nu avem camp used, iar parola noua nu e validata
def reset_password(body: PasswordResetReq):
    conn = get_connection("data.db")

    reset = conn.execute(
        """SELECT * FROM password_reset_tokens
           WHERE reset_token = ? AND expires_at > datetime('now')""",
        (body.reset_token,)
    ).fetchone()

    if not reset:
        conn.close()
        raise HTTPException(status_code=400, detail="Token invalid sau expirat")
    
    hash_nou = weak_password_hash(body.new_password)

    conn.execute(   
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_nou, reset["user_id"])
    )
    # nu marcam in niciun fel tokenul ca folisit

    conn.commit()
    conn.close()

    return {"message": "Parola resetate cu succes"}
