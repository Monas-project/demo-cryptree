import os
import json
import datetime
from cryptography.fernet import Fernet
from fakeIPFS import FakeIPFS
# import ipfshttpclient
import ipfs_api

# 例: 環境変数 'TEST_ENV' が 'True' の場合にのみ実際の接続を行う
# if os.environ.get('TEST_ENV') != 'True':
#     client = ipfshttpclient.connect()
# else:
#     client = FakeIPFS()  # テスト用の偽のIPFSクライアン


class CryptTreeNode:
    def __init__(self, metadata, keydata, subfolder_key):
        self.metadata = metadata
        self.keydata = keydata
        self.subfolder_key = subfolder_key

    @classmethod
    def create_node(self, name, owner_id, isDirectory, parent=None, file_data=None):
        keydata = {}
        subfolder_key = Fernet.generate_key()
        backlink_key = Fernet.generate_key()
        data_key = Fernet.generate_key()

        metadata = {}
        metadata["name"] = name
        # add wallet connect
        metadata["owner_id"] = owner_id
        metadata["creation_data"] = datetime.datetime.now().strftime(
            "%Y/%m/%d %H:%M:%S")
        keydata["enc_backlink_key"] = Fernet(
            subfolder_key).encrypt(backlink_key).decode()

        if parent is not None:
            parent_info = json.dumps({
                "name": parent.metadata["name"],
            }).encode()
            metadata["parent"] = Fernet(
                backlink_key).encrypt(parent_info).decode()
            keydata["enc_subfolder_key"] = Fernet(
                parent.subfolder_key).encrypt(subfolder_key).decode()

        if not isDirectory:
            file_key = Fernet.generate_key()
            keydata["enc_file_key"] = Fernet(
                data_key).encrypt(file_key).decode()

            # ファイルだったら暗号化してfile作成
            enc_file_data = Fernet(
                file_key).encrypt(file_data).decode()
            # file_cid = client.add_json(enc_file_data)
            # 一旦コメントアウト
            file_cid = ipfs_api.publish(enc_file_data)
            metadata["file_cid"] = file_cid
        else:
            metadata["child"] = {}

        keydata["enc_data_key"] = Fernet(
            backlink_key).encrypt(data_key).decode()

        return CryptTreeNode(metadata=metadata, keydata=keydata, subfolder_key=subfolder_key)

    def get_encrypted_metadata(self):
        bk = Fernet(self.subfolder_key).decrypt(
            self.keydata["enc_backlink_key"])
        dk = Fernet(bk).decrypt(self.keydata["enc_data_key"])
        f = Fernet(dk)
        return f.encrypt(json.dumps(self.metadata).encode()).decode()

    def add_node(self, cid, name, path, is_directory):
        if "child" not in self.metadata:
            raise Exception("Only directory node can call this method")

        self.metadata["child"][path] = {
            "metadata_cid": cid,
            "name": name,
            "is_directory": is_directory
        }

    def reencrypt(self, parent_sk: bytes, new_sk: bytes = None):
        if new_sk is None:
            new_sk = Fernet.generate_key()
        new_bk = Fernet.generate_key()
        new_dk = Fernet.generate_key()

        keydata = {}
        keydata["enc_subfolder_key"] = Fernet(
            parent_sk).encrypt(new_sk).decode()
        keydata["enc_backlink_key"] = Fernet(new_sk).encrypt(new_bk).decode()
        keydata["enc_data_key"] = Fernet(new_bk).encrypt(new_dk).decode()

        self.keydata = keydata
        self.subfolder_key = new_sk
    

    def get_decrypt_key(self):
        # 復号化に必要なキーを取得
        bk = Fernet(self.subfolder_key).decrypt(
            self.keydata["enc_backlink_key"].encode())
        dk = Fernet(bk).decrypt(self.keydata["enc_data_key"].encode())

        # Fernetオブジェクトを使用してメタデータを復号化
        f = Fernet(dk)
        return f
