import json, pickle
from fastapi import FastAPI
from cryptography.fernet import Fernet

from fakeIPFS import FakeIPFS 
from cache import CryptreeCache
from cryptree import CryptTreeNode

app = FastAPI()

fake_ipfs = FakeIPFS()
cryptree_cache = CryptreeCache()
node = CryptTreeNode(name="root", isDirectory=True, parent=None)ß

@app.get("/{path}")
def read(path: str):
    if cryptree_cache.contains_key(path):
        return cryptree_cache.get(path)
    
    cid = node.metadata["child"][path]
    encrypted_data = json.loads(fake_ipfs.cat(cid).decode())
    
    key_info = encrypted_data["key"]
    sk = Fernet(node.subfolder_key).decrypt(key_info["enc_subfolder_key"])
    bk = Fernet(sk).decrypt(key_info["enc_backlink_key"])
    dk = Fernet(bk).decrypt(key_info["enc_data_key"])
    
    decrypted_data = Fernet(dk).decrypt(encrypted_data["metadata"])
    cryptree_cache.put(path, decrypted_data)

    return decrypted_data

@app.post("/{path}")
def add_folder(path:str):
    new_node = CryptTreeNode(name=path, isDirectory=True, parent=node)
    data = {
        "key":new_node.keydata,
        "metadata":new_node.get_encrypted_metadata()
    }
    print(data)
    cid = fake_ipfs.add(json.dumps(data).encode())
    node.add_node(new_node, cid)

    return node.metadata

@app.post("/file/{path}")
def add_file(path:str):
    new_node = CryptTreeNode(name=path, isDirectory=False, parent=node, data="hello world")
    data = {
        "key":new_node.keydata,
        "metadata":new_node.get_encrypted_metadata()
    }
    print(data)
    cid = fake_ipfs.add(json.dumps(data).encode())
    node.add_node(new_node, cid)
    return node.metadata

def serialize_object(obj) -> bytes:
    return pickle.dumps(obj)

def deserialize_object(data: bytes):
    return pickle.loads(data)