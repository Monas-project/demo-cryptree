import json, datetime
from cryptography.fernet import Fernet

# For creating cryptree node described in the paper
class CryptTreeNode:
    def __init__(self, metadata, keydata, subfolder_key):
        self.metadata = metadata
        self.keydata = keydata
        self.subfolder_key = subfolder_key
    
    @classmethod
    def create_node(self, name, isDirectory, parent=None, file_cid=None):
        subfolder_key = Fernet.generate_key()
        backlink_key = Fernet.generate_key()
        data_key = Fernet.generate_key()

        keydata = {}
        metadata = {}
        metadata["name"] = name
        metadata["creation_data"] = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        keydata["enc_backlink_key"] = Fernet(subfolder_key).encrypt(backlink_key).decode()

        if parent is not None:
            parent_info = json.dumps({
                "name":parent.metadata["name"],
            }).encode()
            metadata["parent"] = Fernet(backlink_key).encrypt(parent_info).decode()
            keydata["enc_subfolder_key"] = Fernet(parent.subfolder_key).encrypt(subfolder_key).decode()
        
        if isDirectory:
            metadata["child"] = {}
        else:
            metadata["file_cid"] = file_cid

        keydata["enc_data_key"] = Fernet(backlink_key).encrypt(data_key).decode()
        return CryptTreeNode(metadata=metadata, keydata=keydata, subfolder_key=subfolder_key)

    def get_encrypted_metadata(self):
        bk = Fernet(self.subfolder_key).decrypt(self.keydata["enc_backlink_key"])
        dk = Fernet(bk).decrypt(self.keydata["enc_data_key"])
        f = Fernet(dk)
        return f.encrypt(json.dumps(self.metadata).encode()).decode()
    
    def add_node(self, cid, name, path, is_directory):
        if "child" not in self.metadata:
            raise Exception("Only directory node can call this method")

        self.metadata["child"][path] = {
            "metadata_cid":cid,
            "name":name,
            "is_directory":is_directory
        }


