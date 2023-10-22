import json
import copy
import pickle
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet

from fakeIPFS import FakeIPFS
from cache import CryptreeCache
from cryptree import CryptTreeNode
from model import RootRequest, UploadDataRequest, FetchDataRequest, FetchKeyRequest, DecryptRequest, ReencNodeRequest

app = FastAPI()
fake_ipfs = FakeIPFS()
cryptree_cache = CryptreeCache()
current_node = None

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


@app.post("/signup")
def create_root():
    # DID等は、一旦スキップ、TODO
    root = CryptTreeNode.create_node(
        name="root", isDirectory=True, parent=None)
    data = {
        "key": root.keydata,
        "metadata": root.get_encrypted_metadata()
    }
    # ルートのIPFS置き場所はどっかに覚えとおかないといけない希ガス, フロント？バッグ？
    # subfolderキーで暗号化したデータをIPFSに置く
    root_cid = fake_ipfs.add(json.dumps(data).encode())
    # ルート情報を復号化する鍵もどっかに覚えとおかないといけない希ガス, フロント？バッグ？
    return {
        "cid": root_cid,
        "key": root.subfolder_key.decode("utf-8")
    }

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
    current_node = CryptTreeNode(json.loads(
        decrypted_data.decode()), key_info, req.root_key)
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

    if not req.isDirectory:
        file_content = req.data.file.read()

    new_node = CryptTreeNode.create_node(
        name=req.name,
        isDirectory=req.isDirectory,
        parent=current_node,
        # file_cid=req.data_cid
        file_data=file_content
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
            "metadata": parent_node.r()
        }
        print(data)
        cid = fake_ipfs.add(json.dumps(data).encode())
        cryptree_cache.put(parent_path, copy.copy(parent_node))

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
