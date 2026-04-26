from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

from src.vulnerabil.routes_util import router as auth_router
from src.db import db_init, get_connection
from src.models import *


app = FastAPI(title="API vulnerabil", version="1.0vulnerabil")

app.include_router(auth_router)

@app.on_event("startup")
def start():
    db_init("data.db")
    print("Vulerabil pornit pe localhost:8000")




