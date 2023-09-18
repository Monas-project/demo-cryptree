# import os
from cryptography.fernet import Fernet
import json, datetime
from auth import DID, generate_challenge, sign_challenge, verify_signature, PRIVATE_KEY


class CryptTreeNode:
    def __init__(self, name, isDirectory, data=None, parent=None):
        self.subfolder_key = Fernet.generate_key()
        self.backlink_key = Fernet.generate_key()

        self.isDirectory = isDirectory
        self.keydata = {}
        self.metadata = {}
        self.metadata["name"] = name
        self.metadata["creation_data"] = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        self.keydata["enc_backlink_key"] = Fernet(self.subfolder_key).encrypt(self.backlink_key).decode()

        if parent is not None:
            parent_info = json.dumps({
                "name":parent.metadata["name"],
            }).encode()
            self.metadata["parent"] = Fernet(self.backlink_key).encrypt(parent_info).decode()
            self.keydata["enc_subfolder_key"] = Fernet(parent.subfolder_key).encrypt(self.subfolder_key).decode()
    
        self.data_key = Fernet.generate_key()
        self.keydata["enc_data_key"] = Fernet(self.backlink_key).encrypt(self.data_key).decode()

        if isDirectory:
            self.metadata["child"] = {}
        elif data is not None:
            self.metadata["data"] = data
    
    def decrypt_data(self, parent_SKf, data):
        f = Fernet(parent_SKf)
        subfolder_key = f.decrypt(self.keydata["enc_subfolder_key"])
        f = Fernet(subfolder_key)
        backlink_key = f.decrypt(self.keydata["enc_backlink_key"])
        f = Fernet(backlink_key)
        data_key = f.decrypt(self.keydata["enc_data_key"])
        f = Fernet(data_key)
        decrypted_data = f.decrypt(data).decode()
        return decrypted_data


    def add_node(self, node, cid):
        if not self.isDirectory:
            raise Exception("Only directory node can call this method")

        self.metadata["child"][node.metadata["name"]] = cid
        f = Fernet(self.data_key)
        return f.encrypt(json.dumps(self.metadata).encode())
    
    def get_encrypted_metadata(self):
        print(self.metadata)
        f = Fernet(self.data_key)
        return f.encrypt(json.dumps(self.metadata).encode()).decode()


