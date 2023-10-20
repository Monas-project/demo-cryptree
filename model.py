from pydantic import BaseModel
from fastapi import UploadFile


class RootRequest(BaseModel):
    cid: str
    root_key: str


class UploadDataRequest(BaseModel):
    name: str
    path: str  # /foo/bar/c.png
    isDirectory: bool
    # data_cid: str
    data: UploadFile


class FetchDataRequest(BaseModel):
    path: str  # /foo/bar/c.png


class SignInRequest(BaseModel):
    public_key: str


class DecryptRequest(BaseModel):
    data: str
    key: str


class FetchKeyRequest(BaseModel):
    path: str


class ReencNodeRequest(BaseModel):
    path: str
