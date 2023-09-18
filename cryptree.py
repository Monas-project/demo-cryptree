import json, datetime
from cryptography.fernet import Fernet

# For in-memory file system
class PlainNode:
    def __init__(self, metadata=None, subfolder_key=None):
        self.metadata = metadata
        self.subfolder_key = subfolder_key

    def add_node(self, cid, name, path, is_directory):
        if "child" not in self.metadata:
            raise Exception("Only directory node can call this method")

        self.metadata["child"][path] = {
            "cid":cid,
            "name":name,
            "is_directory":is_directory
        }

# For creating cryptree node described in the paper
class CryptTreeNode:
    def __init__(self, name, isDirectory, data=None, parent=None):
        self.subfolder_key = Fernet.generate_key()
        self.backlink_key = Fernet.generate_key()
        self.data_key = Fernet.generate_key()

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
        
        self.keydata["enc_data_key"] = Fernet(self.backlink_key).encrypt(self.data_key).decode()

        if isDirectory:
            self.metadata["child"] = {}
        elif data is not None:
            self.metadata["data"] = data

    def get_encrypted_metadata(self):
        f = Fernet(self.data_key)
        return f.encrypt(json.dumps(self.metadata).encode()).decode()


