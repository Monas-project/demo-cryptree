import json
import copy
import pickle
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import timedelta
import ipfshttpclient

from fakeIPFS import FakeIPFS
from cryptreeCache import CryptreeCache
from cryptree import CryptTreeNode
from auth import AuthLogin
from model import RootRequest, UploadDataRequest, FetchDataRequest, FetchKeyRequest, DecryptRequest, SignInRequest

app = FastAPI()
fake_ipfs = FakeIPFS()
cryptree_cache = CryptreeCache()
current_node = None
# wallet connect追加
w3 = Web3()
ACCESS_TOKEN_EXPIRE_MINUTES = 30
owner_data_map = {}  # owner_id -> user_data

# CORS設定
origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ファイルシステムのルート作成

# @app.post("/auth")
# def authenticate(req: AuthRequest):
#     # Verify the signature


@app.post("/signup")
def create_root(req: SignInRequest):
    # DID等は、一旦スキップ、TODO
    # wallet connect追加
    userAddress = req.address
    if userAddress is None:
        return "You should connect wallet"

    # message = "Please sign this message to log in."
    message = encode_defunct(text="Please sign this message to log in.")
    recovered_address = w3.eth.account.recover_message(
        message, signature=req.signature)

    if recovered_address == userAddress:
        # Authentication successful, create JWT
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = AuthLogin.create_access_token(
            data={"sub": userAddress}, expires_delta=access_token_expires)

        # create root
        owner_id = req.address
        print(owner_id)
        print(req.address)

        root = CryptTreeNode.create_node(
            name="root", isDirectory=True, parent=None, owner_id=owner_id)
        data = {
            "key": root.keydata,
            "metadata": root.get_encrypted_metadata()
        }
        # ルートのIPFS置き場所はどっかに覚えとおかないといけない希ガス, フロント？バッグ？
        client = ipfshttpclient.connect()  # Connects to: /dns/localhost/tcp/5001/http
        print("connected")
        # res = client.add_json(json.dumps(data).encode())
        root_cid = client.add_json(data)
        print("root_cid: ", root_cid)
        root_json = client.get_json(root_cid)
        print("json: ", root_json)
        # ルート情報を復号化する鍵もどっかに覚えとおかないといけない希ガス, フロント？バッグ？

        global owner_data_map
        owner_data_map[owner_id] = {
            "cid": root_cid,
            "key": root.subfolder_key.decode("utf-8")
        }
        print(owner_data_map)

        # return {
        #     "cid": root_cid,
        #     "key": root.subfolder_key.decode("utf-8")
        # }
        # return owner_data_map[owner_id]

        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")


# ファイルシステムのルート取得, ルートの情報があるIPFSのCIDと鍵を渡してもらう想定


@app.post("/login")
def fetch_root(req: RootRequest):
    # add wallet connect
    global owner_data_map, current_node
    print(owner_data_map)
    if req.address not in owner_data_map:
        return "You should sign up"

    owner_id = req.address
    user_data = owner_data_map.get(owner_id)

    encrypted_data = json.loads(fake_ipfs.cat(user_data["cid"]).decode())
    key_info = encrypted_data["key"]

    # Derive key
    sk = user_data["key"]
    bk = Fernet(sk).decrypt(key_info["enc_backlink_key"])
    dk = Fernet(bk).decrypt(key_info["enc_data_key"])

    # Derive metadata
    decrypted_data = Fernet(dk).decrypt(encrypted_data["metadata"])

    # Set root info and cache
    current_node = CryptTreeNode(json.loads(
        decrypted_data.decode()), key_info, user_data["key"])
    cryptree_cache.put("/", current_node)

    return current_node


@app.post("/fetch")
def read(body: FetchDataRequest):
    global current_node
    path = body.path

    if current_node is None:
        return "You should login"

    if cryptree_cache.contains_key(path):
        current_node = cryptree_cache.get(path)
        return current_node.metadata

    print(current_node.metadata)

    if path not in current_node.metadata["child"]:
        return "No data"

    cid = current_node.metadata["child"][path]["metadata_cid"]
    encrypted_data = json.loads(fake_ipfs.cat(cid).decode())

    key_info = encrypted_data["key"]
    sk = Fernet(current_node.subfolder_key).decrypt(
        key_info["enc_subfolder_key"])
    bk = Fernet(sk).decrypt(key_info["enc_backlink_key"])
    dk = Fernet(bk).decrypt(key_info["enc_data_key"])

    decrypted_data = Fernet(dk).decrypt(encrypted_data["metadata"])

    current_node.metadata = json.loads(decrypted_data.decode())
    current_node.keydata = key_info
    current_node.subfolder_key = sk
    cryptree_cache.put(path, copy.copy(current_node))
    print(current_node.metadata)

    return current_node.metadata

# 新規フォルダー・ファイル作成
# TODO recursion


@app.post("/upload")
def upload_data(req: UploadDataRequest):
    global current_node
    if current_node is None:
        return "You should login"

    new_node = CryptTreeNode.create_node(
        name=req.name,
        owner_id=req.id,
        isDirectory=req.isDirectory,
        parent=current_node,
        file_cid=req.data_cid
    )

    data = {
        "key": new_node.keydata,
        "metadata": new_node.get_encrypted_metadata()
    }

    print(data)
    cid = fake_ipfs.add(json.dumps(data).encode())
    current_node.add_node(cid, req.name, req.path, req.isDirectory)

    # TODO recursion
    path = req.path.split("/")
    while len(path) != 1:
        child_path = "/".join(path)
        path.pop()
        parent_path = "/".join(path)
        if parent_path == "":
            parent_path = "/"

        parent_node = None
        if cryptree_cache.contains_key(parent_path):
            parent_node = cryptree_cache.get(parent_path)
        else:
            encrypted_data = json.loads(fake_ipfs.cat(cid).decode())

        print(child_path)
        print(parent_path)
        print(parent_node.metadata)
        parent_node.metadata["child"][child_path]["metadata_cid"] = cid
        data = {
            "key": parent_node.keydata,
            "metadata": parent_node.get_encrypted_metadata()
        }
        print(data)
        cid = fake_ipfs.add(json.dumps(data).encode())
        cryptree_cache.put(parent_path, copy.copy(parent_node))

    return current_node.metadata

# 再暗号化


@app.post("/reencrypt")
def reencrypt():
    pass  # TODO

# 復号化


@app.post("/decrypt")
def decrypt_data(req: DecryptRequest):
    decrypt_key = req.key
    encrypted_data = req.data
    return {
        "data": Fernet(decrypt_key).decrypt(encrypted_data.encode())
    }

# key取得


@app.post("/fetchkey")
def fetch_key(req: FetchKeyRequest):
    global current_node
    path_data = req.path
    print(req.path)
    if current_node is None:
        return "You should login"

    if cryptree_cache.contains_key(path_data):
        print("cache hit")
        current_node = cryptree_cache.get(path_data)
        return {
            "key": current_node.subfolder_key
        }

# Share data


@app.get("/share")
def get_key_for_sharing_data():
    pass  # TODO


@app.get("/cacheclear")
def cache_clear():
    cryptree_cache.clear()

# 以下、まだ使ってないです。無視してください、すみません、消したくないです、PAGNI


def serialize_object(obj) -> bytes:
    return pickle.dumps(obj)


def deserialize_object(data: bytes):
    return pickle.loads(data)
