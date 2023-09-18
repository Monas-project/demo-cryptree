import json, pickle
from fastapi import FastAPI
from cryptography.fernet import Fernet

from fakeIPFS import FakeIPFS 
from cache import CryptreeCache
from cryptree import CryptTreeNode, PlainNode
from model import RootRequest, UploadDataRequest

app = FastAPI()
fake_ipfs = FakeIPFS()
cryptree_cache = CryptreeCache()
current_node = None

# ファイルシステムのルート作成
@app.post("/signup")
def create_root():
    # DID等は、一旦スキップ、TODO
    root = CryptTreeNode(name="root", isDirectory=True, parent=None)
    data = {
        "key":root.keydata,
        "metadata":root.get_encrypted_metadata()
    }
    root_cid = fake_ipfs.add(json.dumps(data).encode()) # ルートのIPFS置き場所はどっかに覚えとおかないといけない希ガス, フロント？バッグ？
    return root_cid, root.subfolder_key # ルート情報を復号化する鍵もどっかに覚えとおかないといけない希ガス, フロント？バッグ？

# ファイルシステムのルート取得, ルートの情報があるIPFSのCIDと鍵を渡してもらう想定
@app.post("/login")
def fetch_root(req: RootRequest):
    encrypted_data = json.loads(fake_ipfs.cat(req.cid).decode())
    key_info = encrypted_data["key"]

    # Derive key
    sk = req.root_key
    bk = Fernet(sk).decrypt(key_info["enc_backlink_key"])
    dk = Fernet(bk).decrypt(key_info["enc_data_key"])
    
    # Derive metadata
    decrypted_data = Fernet(dk).decrypt(encrypted_data["metadata"])

    # Set root info and cache
    global current_node
    current_node = PlainNode(json.loads(decrypted_data.decode()), req.root_key)
    cryptree_cache.put("#", current_node)
    
    return decrypted_data

@app.get("/{path}")
def read(path: str):
    global current_node
    if current_node is None:
        return "You should login"
    
    if cryptree_cache.contains_key(path):
        current_node = cryptree_cache.get(path)
        return current_node.metadata
    
    print(current_node.metadata)

    if path not in current_node.metadata["child"]:
        return "No data"

    cid = current_node.metadata["child"][path]["cid"]
    encrypted_data = json.loads(fake_ipfs.cat(cid).decode())
    
    key_info = encrypted_data["key"]
    sk = Fernet(current_node.subfolder_key).decrypt(key_info["enc_subfolder_key"])
    bk = Fernet(sk).decrypt(key_info["enc_backlink_key"])
    dk = Fernet(bk).decrypt(key_info["enc_data_key"])
    
    decrypted_data = Fernet(dk).decrypt(encrypted_data["metadata"])

    current_node.metadata = json.loads(decrypted_data.decode())
    current_node.subfolder_key = sk
    cryptree_cache.put(path, current_node)

    return decrypted_data

# 新規フォルダー・ファイル作成
# TODO recursion
@app.post("/upload")
def upload_data(req: UploadDataRequest):
    global current_node
    if current_node is None:
        return "You should login"

    new_node = None
    if req.isDirectory:
        new_node = CryptTreeNode(name=req.name, isDirectory=True, parent=current_node)
    else:
        new_node = CryptTreeNode(name=req.name, isDirectory=False, parent=current_node, data=req.data)

    data = {
        "key":new_node.keydata,
        "metadata":new_node.get_encrypted_metadata()
    }

    print(data)
    cid = fake_ipfs.add(json.dumps(data).encode())
    current_node.add_node(cid, req.name, req.path, req.isDirectory)

    # TODO recursion
    # path = req.path.split("/")
    # while len(path) != 0:
    #     node.get_encrypted_metadata()
    #     fake_ipfs.add(json.dumps(data).encode())
        
    return current_node.metadata

# 再暗号化
@app.post("/reencrypt")
def reencrypt():
    pass # TODO

# Share data
@app.get("/share")
def get_key_for_sharing_data():
    pass # TODO

# 以下、まだ使ってないです。無視してください、すみません、消したくないです、PAGNI
def serialize_object(obj) -> bytes:
    return pickle.dumps(obj)

def deserialize_object(data: bytes):
    return pickle.loads(data)