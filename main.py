import json
import copy
import pickle
from fastapi import FastAPI, HTTPException, status, Form, UploadFile, File
from typing import List
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import timedelta
import ipfshttpclient

# from fakeIPFS import FakeIPFS
from cryptreeCache import CryptreeCache
from cryptree import CryptTreeNode
from auth import AuthLogin
from model import RootRequest, UploadDataRequest, FetchDataRequest, FetchKeyRequest, DecryptRequest, ReencNodeRequest, SignInRequest

app = FastAPI()
# fake_ipfs = FakeIPFS()
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
client = ipfshttpclient.connect()


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
        # client = ipfshttpclient.connect()  # Connects to: /dns/localhost/tcp/5001/http
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
    print("user_data", user_data)
    print(user_data["cid"])

    encrypted_data = json.loads(client.cat(user_data["cid"]))
    print("encrypted_data", encrypted_data)
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
    print("login current_node", current_node)
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
    # encrypted_data = json.loads(fake_ipfs.cat(cid).decode())
    encrypted_data = json.loads(client.cat(cid))
    print("fetch : ", encrypted_data)

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
def upload_data(
    name: str = Form(),
    id: str = Form(),
    path: str = Form(),
    isDirectory: bool = Form(),
    data: List[UploadFile] = File([]),
    # data: UploadFile = File(),
):
    req = UploadDataRequest(
        name=name,
        id=id,
        path=path,
        isDirectory=isDirectory,
        data=data
    )
# def upload_data(req: UploadDataRequest):
    print("uploadのreq: ", req)
    global current_node
    print("current_node: ", current_node)
    file_content = None
    if current_node is None:
        return "You should login"

    if not req.isDirectory:
        # file_content = req.data.file.read()
        for file in req.data:
            file_content = file.file.read()
            print("file_content: ", file_content)

    new_node = CryptTreeNode.create_node(
        name=req.name,
        owner_id=req.id,
        isDirectory=req.isDirectory,
        parent=current_node,
        # file_cid=req.data_cid
        file_data=file_content
    )
    print("new_node: ", new_node)

    data = {
        "key": new_node.keydata,
        "metadata": new_node.get_encrypted_metadata()
    }
    print("data[metadata]: ", data["metadata"])

    cid = client.add_json(data)
    print("cid: ", cid)

    current_node.add_node(cid, req.name, req.path, req.isDirectory)

    # TODO recursion
    path = req.path.split("/")
    while len(path) != 1:
        child_path = "/".join(path)
        print("upload の child_path: ", child_path)
        path.pop()
        print("upload の pop後のpath: ", path)
        parent_path = "/".join(path)
        print("upload の pop後のparent_path: ", parent_path)
        if parent_path == "":
            parent_path = "/"

        print("upload の parent_path: ", parent_path)

        parent_node = None
        if cryptree_cache.contains_key(parent_path):
            print("ifの中はいりましたーー！")
            parent_node = cryptree_cache.get(parent_path)
        else:
            print("elseの中はいりましたーー！")
            encrypted_data = json.loads(client.cat(cid).decode())

        print(child_path)
        print(parent_path)
        # print(parent_node.metadata)
        if parent_node is None:
            raise ValueError("parent_nodeがNoneです!")
        parent_node.metadata["child"][child_path]["metadata_cid"] = cid
        data = {
            "key": parent_node.keydata,
            "metadata": parent_node.get_encrypted_metadata()
        }
        print("parent_node", data)
        cid = client.add_json(data)
        print("parent_cid: ", cid)
        cryptree_cache.put(parent_path, copy.copy(parent_node))
    
    print("これリターンするcurrent_node.metadata", current_node.metadata)

    return current_node.metadata

# 再暗号化


@app.post("/reencrypt")
def reencrypt(req: ReencNodeRequest):
    return reenc(req.path)


# 復号化


@app.post("/decrypt")
def decrypt_data(req: DecryptRequest):
    decrypt_key = req.key
    encrypted_data = req.data
    return {
        "data": decrypt_key.decrypt(encrypted_data.encode())
    }

# key取得


@app.post("/fetchkey")
def fetch_key(req: FetchKeyRequest):
    print("fetchkeyのreq: ", req)
    global current_node
    path_data = req.path
    print(req.path)
    print("current_node: ", current_node)
    if current_node is None:
        print("You should login")
        return "You should login"

    print("クリプトツリーから取得")
    print("cryptree_cache.contains_key(path_data)", cryptree_cache.contains_key(path_data))
    if cryptree_cache.contains_key(path_data):
        print("cache hit")
        current_node = cryptree_cache.get(path_data)
        print("decrypt_key", current_node.get_decrypt_key)
        print("metadata", current_node.metadata)
        return {
            "decrypt_key": current_node.get_decrypt_key,
            "metadata": current_node.metadata
        }
    print("cache miss")
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


def reenc(path: str, parent_sk=None, is_directory=False):
    current_node = None
    if cryptree_cache.contains_key(path):
        current_node = cryptree_cache.get(path)
    else:
        pass  # TODO

    if parent_sk is None:
        tmp = path.split("/")
        tmp.pop()
        parent_path = "/".join(tmp)
        if parent_path == "":
            parent_path = "/"

        parent_node = None
        if cryptree_cache.contains_key(parent_path):
            parent_node = cryptree_cache.get(parent_path)
        else:
            pass  # TODO
        parent_sk = parent_node.subfolder_key

    if not is_directory:
        current_node.reencrypt(parent_sk=parent_sk)
        data = {
            "key": current_node.keydata,
            "metadata": current_node.get_encrypted_metadata()
        }
        cid = fake_ipfs.add(json.dumps(data).encode())
        cryptree_cache.put(path, copy.copy(current_node))
        return cid

    new_sk = Fernet.generate_key()
    for child in current_node.metadata["child"].keys():
        cid = reenc(child, new_sk,
                    current_node.metadata["child"][child].isDirectory)
        current_node["child"][child]["metadata_cid"] = cid

    current_node.reencrypt(parent_sk=parent_sk, new_sk=new_sk)
    data = {
        "key": current_node.keydata,
        "metadata": current_node.get_encrypted_metadata()
    }
    cid = fake_ipfs.add(json.dumps(data).encode())
    cryptree_cache.put(path, copy.copy(current_node))

    return cid
