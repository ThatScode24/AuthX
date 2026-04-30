from src.models import *
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, HTTPException
from jose import jwt 
from src.db import get_connection, log_event, request_meta
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
    ip, ua = request_meta(request)
    conn  = get_connection("data_vulnerabil.db")
    user = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()

    if not user:
        conn.close()
        log_event("data_vulnerabil.db", "LOGIN_FAIL", category="AUTH",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes=f"unknown email: {body.email}")
        raise HTTPException(status_code=401, detail="Utilizator inexistent")

    password_hash = weak_password_hash(body.password)

    if user["password_hash"] != password_hash:
        conn.close()
        log_event("data_vulnerabil.db", "LOGIN_FAIL", user_id=user["id"], category="AUTH",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes="wrong password")
        raise HTTPException(status_code=401, detail="Parola incorecta")

    tok = create_weak_token(user["id"], user["email"], user["role"])

    conn.execute(
        """INSERT INTO user_sessions (user_id, session_token, expires_at)
           VALUES (?, ?, datetime('now', '+100 years'))""",
        (user["id"], tok)
    )
    conn.commit()
    conn.close()

    log_event("data_vulnerabil.db", "LOGIN_SUCCESS", user_id=user["id"], category="AUTH",
              ip_address=ip, user_agent=ua)

    return {"access_token": tok, "token_type": "bearer"}

# vulnerabilitate: marcam sesiunea ca invalidata in DB, dar tokenul JWT este self-contained
# si nu verificam tabela user_sessions in get_current_user → tokenul "deconectat" inca functioneaza
@router.post("/logout", response_model=ApiResp)
def logout(request: Request):
    ip, ua = request_meta(request)
    auth = request.headers.get("Authorization") or ""
    token = auth.split(" ", 1)[1] if auth.startswith("Bearer ") else None
    user_id = None

    if token:
        conn = get_connection("data_vulnerabil.db")
        sess = conn.execute(
            "SELECT user_id FROM user_sessions WHERE session_token = ?", (token,)
        ).fetchone()
        if sess:
            user_id = sess["user_id"]
            conn.execute(
                "UPDATE user_sessions SET is_invalidated = 1 WHERE session_token = ?",
                (token,)
            )
            conn.commit()
        conn.close()

    log_event("data_vulnerabil.db", "LOGOUT", user_id=user_id, category="AUTH",
              ip_address=ip, user_agent=ua,
              notes="vulnerabil: sesiune marcata invalidata, dar JWT inca acceptat")
    return { "message": ' Logged out'}


@router.post("/register", response_model=ApiResp) # nu verificam complexitatea paroleisi stocam parola ca md fara salt
def register(body: RegisterReq, request: Request):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    exista_deja = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()

    if exista_deja:
        conn.close()
        log_event("data_vulnerabil.db", "REGISTER", user_id=exista_deja["id"], category="AUTH",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes=f"email deja folosit: {body.email}")
        raise HTTPException(status_code=400, detail="Email deja folosit")

    hash_parola = weak_password_hash(body.password)

    cur = conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'ANALYST')",
        (body.email, hash_parola)
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_event("data_vulnerabil.db", "REGISTER", user_id=new_id, category="AUTH",
              ip_address=ip, user_agent=ua, notes=body.email)

    return {"message": "User registered successfully"}



@router.post("/forgot-password", response_model=ApiResp)  # aici expunem existenta sau nu a emailului, iar tokenul este predicatable (timestamp)
def parola_uitata(body: ForgotPasswordReq, request: Request):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    user = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()
    if not user:
        conn.close()
        log_event("data_vulnerabil.db", "PASSWORD_RESET_REQUEST", category="AUTH",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  notes=f"email inexistent: {body.email}")
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

    log_event("data_vulnerabil.db", "PASSWORD_RESET_REQUEST", user_id=user["id"], category="AUTH",
              ip_address=ip, user_agent=ua, target_id=reset_token)

    return {"message": f"Password reset token: {reset_token}"}

@router.post("/reset-password", response_model=ApiResp)  # token care expira dar e reutilizabil,nu avem camp used, iar parola noua nu e validata
def reset_password(body: PasswordResetReq, request: Request):
    ip, ua = request_meta(request)
    conn = get_connection("data_vulnerabil.db")

    reset = conn.execute(
        """SELECT * FROM password_reset_tokens
           WHERE reset_token = ? AND expires_at > datetime('now')""",
        (body.reset_token,)
    ).fetchone()

    if not reset:
        conn.close()
        log_event("data_vulnerabil.db", "PASSWORD_RESET", category="AUTH",
                  ip_address=ip, user_agent=ua, outcome="FAILURE",
                  target_id=body.reset_token, notes="token invalid sau expirat")
        raise HTTPException(status_code=400, detail="Token invalid sau expirat")

    hash_nou = weak_password_hash(body.new_password)

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_nou, reset["user_id"])
    )
    # nu marcam in niciun fel tokenul ca folisit

    conn.commit()
    conn.close()

    log_event("data_vulnerabil.db", "PASSWORD_RESET", user_id=reset["user_id"], category="AUTH",
              ip_address=ip, user_agent=ua, target_id=body.reset_token)

    return {"message": "Parola resetate cu succes"}
