from pydantic import BaseModel

class RootRequest(BaseModel):
    cid: str
    root_key: str

class UploadDataRequest(BaseModel):
    name: str
    path: str
    isDirectory: bool
    data: str