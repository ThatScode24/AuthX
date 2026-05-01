
import os
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Response, HTTPException
from jose import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv

from src.models import AuthTokenResponse, ApiResp, RegisterReq, LoginReq,ForgotPasswordReq, PasswordResetReq

from src.db import get_connection, log_event, request_meta


# aici avem lucrurile din .env - in mod normal l-am pune in .gitignore, dar il includem in repo pentru exemplu

load_dotenv()

DB_PATH = os.environ["DB_PATH"]
SECRET_KEY = os.environ["SECRET_KEY"]
ALG = os.environ["JWT_ALG"]

TOKEN_TTL_MINUTES = int(os.environ["TOKEN_TTL_MINUTES"])
RESET_TOKEN_TTL_MINUTES = int(os.environ["RESET_TOKEN_TTL_MINUTES"])
LOCKOUT_MINUTES = int(os.environ["LOCKOUT_MINUTES"])
MAX_LOGIN_ATTEMPTS = int(os.environ["MAX_LOGIN_ATTEMPTS"])
parola_MIN_LEN = int(os.environ["PAROLA_MIN_LEN"])

GENERIC_AUTH_FAIL = "Credentiale invalide"
GENERIC_RESET_OK = "Daca emailul este inregistrat, vei primi instructiuni de resetare"

ph = PasswordHasher()
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/auth", tags=["auth|securizat"])



def validate_password(parola):  # verificare parola
    if len(parola) < parola_MIN_LEN:
        raise HTTPException(400, f"Parola trebuie sa aiba minim {parola_MIN_LEN} caractere")
    if not any(c.islower() for c in parola):
        raise HTTPException(400, "Parola trebuie sa contina litere mici")
    if not any(c.isupper() for c in parola):
        raise HTTPException(400, "Parola trebuie sa contina litere mari")
    if not any(c.isdigit() for c in parola):
        raise HTTPException(400, "Parola trebuie sa contina cifre")
    if not any(not c.isalnum() for c in parola):
        raise HTTPException(400, "Parola trebuie sa contina simboluri")


def hash_password(parola):
    return ph.hash(parola)


def verify_password(stored_hash, parola):
    try:
        ph.verify(stored_hash, parola)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def make_token(user_id, email, role):
    now = datetime.utcnow()
    expires = now + timedelta(minutes=TOKEN_TTL_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": expires,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALG), expires


def is_currently_locked(user):
    if not user["is_locked"]:
        return False
    locked_until = user["locked_until"]
    if not locked_until:
        return True
    try:
        until = datetime.fromisoformat(locked_until)
    except ValueError:
        return True
    return datetime.utcnow() < until


# notam introducerea unei limite de 5 min
@router.post("/register", response_model=ApiResp)
@limiter.limit("5/minute")
def register(request: Request, body: RegisterReq):
    ip, ua = request_meta(request)
    validate_password(body.password)

    conn = get_connection(DB_PATH)
    exista = conn.execute("SELECT id FROM users WHERE email=?", (body.email,)).fetchone()
    if exista:
        conn.close()
        log_event(DB_PATH, "REGISTER", category="AUTH", outcome="FAILURE",
                  ip_address=ip, user_agent=ua, notes="email duplicat")
        raise HTTPException(400, "Email deja folosit")

    h = hash_password(body.password)
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'ANALYST')",
        (body.email, h)
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_event(DB_PATH, "REGISTER", user_id=new_id, category="AUTH",
              ip_address=ip, user_agent=ua, notes=body.email)
    return {"message": "Cont creat"}


@router.post("/login", response_model=AuthTokenResponse)
@limiter.limit("10/minute")
def login(request: Request, response: Response, body: LoginReq):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)
    user = conn.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()

    if not user:  # protejare impotriva atacurilor de timing, argon2 e lent intentionat asadar atacatorul nu are cum sa si dea seama daca exista mailul sau nu
        try:
            ph.verify(
                "$argon2id$v=19$m=65536,t=3,p=4$"
                "ZHVtbXlzYWx0c2FsdHNhbHQ$"
                "0000000000000000000000000000000000000000000",
                "dummy"
            )
        except Exception:
            pass
        conn.close()
        log_event(DB_PATH, "LOGIN_FAIL", category="AUTH", outcome="FAILURE",
                  ip_address=ip, user_agent=ua, notes="email inexistent")
        raise HTTPException(401, GENERIC_AUTH_FAIL)

    if is_currently_locked(user):
        conn.close()
        log_event(DB_PATH, "LOGIN_FAIL", user_id=user["id"], category="AUTH",
                  outcome="FAILURE", ip_address=ip, user_agent=ua,
                  notes="cont blocat temporar")
        raise HTTPException(401, GENERIC_AUTH_FAIL)

    if user["is_locked"]:
        conn.execute(
            "UPDATE users SET is_locked=0, login_attempts=0, locked_until=NULL WHERE id=?",
            (user["id"],)
        )
        conn.commit()

    if not verify_password(user["password_hash"], body.password):
        attempts = user["login_attempts"] + 1
        if attempts >= MAX_LOGIN_ATTEMPTS:
            until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()  # setam is_locked daca utilizatorul a gresit creditentialele de prea multe ori
            conn.execute(
                "UPDATE users SET is_locked=1, login_attempts=?, locked_until=? WHERE id=?",
                (attempts, until, user["id"])
            )
        else:
            conn.execute(
                "UPDATE users SET login_attempts=? WHERE id=?",
                (attempts, user["id"])
            )
        conn.commit()
        conn.close()
        log_event(DB_PATH, "LOGIN_FAIL", user_id=user["id"], category="AUTH",
                  outcome="FAILURE", ip_address=ip, user_agent=ua,
                  notes=f"parola invalida, attempts={attempts}")
        raise HTTPException(401, GENERIC_AUTH_FAIL)

    # login success: resetam limitele de securitate
    conn.execute(
        "UPDATE users SET login_attempts=0, is_locked=0, locked_until=NULL WHERE id=?",
        (user["id"],)
    )

    # aici invalidam sesiunile anterioare
    conn.execute(
        "UPDATE user_sessions SET is_invalidated=1 WHERE user_id=? AND is_invalidated=0",
        (user["id"],)
    )

    tok, expires = make_token(user["id"], user["email"], user["role"])
    conn.execute(
        """INSERT INTO user_sessions (user_id, session_token, expires_at, user_agent)
           VALUES (?, ?, ?, ?)""",
        (user["id"], tok, expires.isoformat(), ua)
    )
    conn.commit()
    conn.close()

    log_event(DB_PATH, "LOGIN_SUCCESS", user_id=user["id"], category="AUTH",
              ip_address=ip, user_agent=ua)
    response.set_cookie(
        key="session",
        value=tok,
        max_age=TOKEN_TTL_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return {"access_token": tok, "token_type": "bearer"}


@router.post("/logout", response_model=ApiResp)
def logout(request: Request, response: Response):
    ip, ua = request_meta(request)
    auth = request.headers.get("Authorization") or ""
    token = auth.split(" ", 1)[1] if auth.startswith("Bearer ") else None
    user_id = None

    if token:
        conn = get_connection(DB_PATH)
        sess = conn.execute(
            "SELECT user_id FROM user_sessions WHERE session_token=?", (token,)
        ).fetchone()
        if sess:
            user_id = sess["user_id"]
            conn.execute(
                "UPDATE user_sessions SET is_invalidated=1 WHERE session_token=?",
                (token,)
            )
            conn.commit()
        conn.close()

    log_event(DB_PATH, "LOGOUT", user_id=user_id, category="AUTH",
              ip_address=ip, user_agent=ua)
    response.delete_cookie(key="session", path="/")
    return {"message": "Logged out"}


@router.post("/forgot-password", response_model=ApiResp)
@limiter.limit("3/minute")
def forgot(request: Request, body: ForgotPasswordReq):
    ip, ua = request_meta(request)
    conn = get_connection(DB_PATH)
    user = conn.execute("SELECT id FROM users WHERE email=?", (body.email,)).fetchone()

    if user:
        # invalidam token-urile vechi neutilizate
        conn.execute(
            "UPDATE password_reset_tokens SET is_used=1 WHERE user_id=? AND is_used=0",
            (user["id"],)
        )
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
        conn.execute(
            """INSERT INTO password_reset_tokens
               (user_id, reset_token, expires_at, requested_from_ip)
               VALUES (?, ?, ?, ?)""",
            (user["id"], token, expires.isoformat(), ip)
        )
        conn.commit()
        # ar fi trebuit trimis prin mail dar logam in aduti aici
        log_event(DB_PATH, "PASSWORD_RESET_REQUEST", user_id=user["id"],
                  category="AUTH", ip_address=ip, user_agent=ua,
                  target_id=token,
                  notes="token (in productie ar fi trimis prin mail)")
    else:
        log_event(DB_PATH, "PASSWORD_RESET_REQUEST", category="AUTH",
                  outcome="FAILURE", ip_address=ip, user_agent=ua,
                  notes=f"email inexistent: {body.email}")

    conn.close()
    # mesaj GENERIC indiferent de existenta
    return {"message": GENERIC_RESET_OK}


@router.post("/reset-password", response_model=ApiResp)
@limiter.limit("5/minute")
def reset(request: Request, body: PasswordResetReq):
    ip, ua = request_meta(request)
    validate_password(body.new_password)

    conn = get_connection(DB_PATH)
    row = conn.execute(
        """SELECT * FROM password_reset_tokens
           WHERE reset_token=? AND is_used=0 AND expires_at > ?""",
        (body.reset_token, datetime.utcnow().isoformat())
    ).fetchone()

    if not row:
        conn.close()
        log_event(DB_PATH, "PASSWORD_RESET", category="AUTH", outcome="FAILURE",
                  ip_address=ip, user_agent=ua, target_id=body.reset_token,
                  notes="token invalid/expirat/folosit")
        raise HTTPException(400, "Token invalid sau expirat")

    new_hash = hash_password(body.new_password)

    conn.execute(
        "UPDATE password_reset_tokens SET is_used=1 WHERE id=?",
        (row["id"],)
    )
    conn.execute(
        """UPDATE users
           SET password_hash=?, login_attempts=0, is_locked=0, locked_until=NULL
           WHERE id=?""",
        (new_hash, row["user_id"])
    )
    # invalidam toate sesiunile active ale userului
    conn.execute(
        "UPDATE user_sessions SET is_invalidated=1 WHERE user_id=? AND is_invalidated=0",
        (row["user_id"],)
    )
    conn.commit()
    conn.close()

    log_event(DB_PATH, "PASSWORD_RESET", user_id=row["user_id"], category="AUTH",
              ip_address=ip, user_agent=ua, target_id=body.reset_token)
    return {"message": "Parola schimbata cu succes"}
