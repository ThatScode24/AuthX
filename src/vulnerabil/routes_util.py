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

def weak_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # un hash de acest tip este atacabil cu rainbow tables 
