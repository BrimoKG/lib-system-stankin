from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    username: str
    password: str
    role: str # admin, moderator, or viewer

class UserResponse(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class BookBase(BaseModel):
    title: str
    author: str
    isbn: str

class BookCreate(BookBase):
    pass

class BookResponse(BaseModel):
    id: int
    title: str
    author: str
    isbn: str
    is_available: bool

    class Config:
        from_attributes = True

#--------SIgnature requests
class ClientSignatureRequest(BaseModel):
    message: str
    signature: str # The Base64 encoded signature
    public_key: str # The client's public key in PEM format

class ServerSignatureResponse(BaseModel):
    message: str
    signature: str
    server_public_key: str
