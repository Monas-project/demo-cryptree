# import os
from cryptography.fernet import Fernet
import json


class CryptTree:
    def __init__(self, name, controller_did, parent=None, location_uri=None,filename=None):
        self.name = name
        self.controller_did = controller_did # cryptreeを制御するDID
        self.parent = None
        self.location_uri = location_uri
        self.filename = filename
        self.accessors = {}  # Users who can access this node

        if parent:
            # Inherit all keys except BKf from parent
            self.DKf = parent.DKf
            self.BKf = Fernet.generate_key()
            self.SKf = parent.SKf
            self.FKf = parent.FKf
            self.CKf = parent.CKf
        else:
            self.DKf = Fernet.generate_key() # Data Key
            self.BKf = Fernet.generate_key() # Backlink Key
            self.SKf = Fernet.generate_key() # Subfolder Key
            self.FKf = Fernet.generate_key() # File Key
            self.CKf = Fernet.generate_key() # Clearance Key (Optional)

    def grant_access(self, user):
        self.accessors[user.name] = user
        user.keys[self.name] = (self.DKf, self.BKf, self.SKf, self.FKf, self.CKf)

    def revoke_access(self, user):
        if user.name in self.accessors:
            del self.accessors[user.name]
            del user.keys[self.name]


class User:
    def __init__(self, name):
        self.name = name
        self.keys = {}


class File(CryptTree):
    def __init__(self, name, data, parent=None, location_uri=None, filename=None):
        super().__init__(name, parent,location_uri=location_uri,filename=filename)
        self.data = data
        self.parent_link = None

    def encrypt_data(self):
        f = Fernet(self.DKf)
        encrypted_data = f.encrypt(self.data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        f = Fernet(self.DKf)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    
    #JSONの暗号化
    def encrypt_metadata(self):
    #metadataはファイル名、作成日時、保存場所
        metadata = {
            "filename": self.filename,
            "creation_date": "some_date",
            "location": self.location_uri
        }

        metadata_json = json.dumps(metadata).encode()
        f = Fernet(self.FKf)
        encrypted_metadata = f.encrypt(metadata_json)
        return encrypted_metadata


class Folder(CryptTree):
    def __init__(self, name, parent=None):
        super().__init__(name, parent)
        self.files = []
        self.folders = []
        self.child_bkfs = {}

    def add_file(self, file):
        self.files.append(file)
        file.parent = self
        file.BKf = Fernet.generate_key()
        file.SKf = self.SKf
        file.FKf = self.FKf

        #子ファイルのBKfを保持
        self.child_bkfs[file.name] = file.BKf

        #BKfで親の名前を隠している
        f = Fernet(self.BKf)
        encrypted_link = f.encrypt(file.name.encode())
        file.parent_link = encrypted_link

    def add_folder(self, folder):
        self.folders.append(folder)
        folder.parent = self
        folder.BKf = Fernet.generate_key()
        folder.SKf = self.SKf
        folder.FKf = self.FKf

        #BKfで親の名前を隠している
        f = Fernet(folder.BKf)
        encrypted_link = f.encrypt(folder.name.encode())
        folder.parent_link = encrypted_link

    def encrypt_metadata(self):
        #metadataはフォルダ名、作成日時
        metadata = {
            "foldername": self.name,
            "creation_date": "some_date",
        }

        metadata_json = json.dumps(metadata).encode()
        f = Fernet(self.SKf)
        encrypted_metadata = f.encrypt(metadata_json)
        return encrypted_metadata

# テスト用の関数


def main():
    user1 = User("User1")
    user2 = User("User2")
    
    controller_did = "did:key:xyz"
    root_folder = Folder("Root", controller_did)
    folder1 = Folder("Folder1", parent=root_folder)
    file1 = File("File1", "Data of File1", parent=folder1, location_uri="ipfs://CID1", filename="document.txt")
    folder1.add_file(file1)
    root_folder.add_folder(folder1)

    folder2 = Folder("Folder2", parent=root_folder)
    file2 = File("File2", "Data of File2", parent=folder2)
    folder2.add_file(file2)
    root_folder.add_folder(folder2)

    folder1.grant_access(user1)
    folder2.grant_access(user2)

    print("User1's keys:", user1.keys)
    print("User2's keys:", user2.keys)

    # ファイルの暗号化と復号化のテスト
    encrypted_data = file1.encrypt_data()
    print("Encrypted data:", encrypted_data)
    decrypted_data = file1.decrypt_data(encrypted_data)
    print("Decrypted data:", decrypted_data)                                                                                                                                                                                                                            


if __name__ == "__main__":
    main()
