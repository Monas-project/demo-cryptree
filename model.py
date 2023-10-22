from pydantic import BaseModel
from fastapi import UploadFile


# class AuthRequest(BaseModel):
#     address: str
# signature: str


class Token(BaseModel):
    access_token: str
    token_type: str


class SignInRequest(BaseModel):
    address: str
    signature: str


# class RootRequest(BaseModel):
#     cid: str
#     root_key: str

class RootRequest(BaseModel):
    address: str


class UploadDataRequest(BaseModel):
    name: str
    id: str
    path: str  # /foo/bar/c.png
    isDirectory: bool
    # data_cid: str
    data: UploadFile


class FetchDataRequest(BaseModel):
    path: str  # /foo/bar/c.png


class DecryptRequest(BaseModel):
    data: str
    key: str


class FetchKeyRequest(BaseModel):
    path: str


class ReencNodeRequest(BaseModel):
    path: str
    is_directory: bool
