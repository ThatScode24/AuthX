from pydantic import BaseModel
from typing import Optional


class NewTicket(BaseModel):
    title: str
    description: str
    severity: str

class TicketPatch(BaseModel):    # optional pentru ca e un update partial, nu trimitem imperativ toate campurile
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None


class RegisterReq(BaseModel):
    email: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str

class PasswordResetReq(BaseModel):
    reset_token: str
    new_password: str

class ForgotPasswordReq(BaseModel):
    email: str

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ApiResp(BaseModel):
    message: str

class ApiError(BaseModel):
    detail: str