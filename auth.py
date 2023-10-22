from fastapi import FastAPI
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel
# from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta


app = FastAPI()


SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"


class AuthLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    @classmethod
    def create_access_token(self, data: dict, expires_delta: timedelta = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
