import json
import datetime
from cryptography.fernet import Fernet
from fakeIPFS import FakeIPFS
import ipfshttpclient

# For creating cryptree node described in the paper
fake_ipfs = FakeIPFS()
#IPFSが使えないから一時的にコメントアウト
#client = ipfshttpclient.connect()


class CryptTreeNode:
    def __init__(self, metadata, keydata, subfolder_key, fake_ipfs):
        self.metadata = metadata
        self.keydata = keydata
        self.subfolder_key = subfolder_key
        self.ipfs_client = fake_ipfs #IPFSが起動できないから一時的に追加

    @classmethod
    def create_node(self, name, owner_id, isDirectory, ipfs_client, parent=None, file_data=None):
        keydata = {}
        subfolder_key = Fernet.generate_key()
        backlink_key = Fernet.generate_key()
        data_key = Fernet.generate_key()
        # ファイルだったらfk作成
        # file_key = None
        # if not isDirectory:
        #     file_key = Fernet.generate_key()
        #     keydata["enc_file_key"] = Fernet(
        #         data_key).encrypt(file_key).decode()

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

        # if isDirectory:
        #     metadata["child"] = {}
        # else:
        #     # ファイルだったら暗号化してfile作成
        #     enc_file_data = Fernet(
        #         file_key).encrypt(file_data).decode()
        #     file_cid = fake_ipfs.add(enc_file_data)
        #     metadata["file_cid"] = file_cid

        if not isDirectory:
            file_key = Fernet.generate_key()
            keydata["enc_file_key"] = Fernet(
                data_key).encrypt(file_key).decode()

            # ファイルだったら暗号化してfile作成
            enc_file_data = Fernet(
                file_key).encrypt(file_data).decode()
            file_cid = ipfs_client.add(enc_file_data) #一旦FakeIPFSを使用するためaddに変更
            metadata["file_cid"] = file_cid
        else:
            metadata["child"] = {}

        keydata["enc_data_key"] = Fernet(
            backlink_key).encrypt(data_key).decode()

        return CryptTreeNode(metadata=metadata, keydata=keydata, subfolder_key=subfolder_key, fake_ipfs=ipfs_client)

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

    def find_deepest_node(self):
        if "child" in self.metadata and self.metadata["child"]:
            for child_key, child_info in self.metadata["child"].items():
                child_cid = child_info["metadata_cid"]
                child_metadata_json = self.ipfs_client.cat(child_cid).decode('utf-8')
                child_metadata = json.loads(child_metadata_json)
                child_node = CryptTreeNode(metadata=child_metadata, keydata={}, subfolder_key="", fake_ipfs=self.ipfs_client)
                return child_node.find_deepest_node()
        else:
            return self


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
