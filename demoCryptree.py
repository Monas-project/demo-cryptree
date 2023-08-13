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
            self.parent = parent
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
    
    #リンクの暗号化(親ノードの名前の暗号化)
    def encrypt_parent_name(self):
        if self.parent:
            f = Fernet(self.BKf)
            encrypted_parent_name = f.encrypt(self.parent.name.encode())
            return encrypted_parent_name
        return None
    
    # 親ノードの名前を復号化
    def decrypt_parent_name(self, encrypted_parent_name):
        f = Fernet(self.BKf)
        decrypted_parent_name = f.decrypt(encrypted_parent_name).decode()
        return decrypted_parent_name
    
    def find_nodes_to_reencrypt(self, target_node):
        nodes_to_reenctypt = [target_node]

        #対象ノードの子孫ノード再帰的に追加(特定ノードとその子孫ノードを全て返す)
        def collet_children(node):
            if isinstance(node, Folder):
                for child_file in node.files:
                    nodes_to_reenctypt.append(child_file)
                    collet_children(child_file)
                for child_folder in node.folders:
                    nodes_to_reenctypt.append(child_folder)
                    collet_children(child_folder)

        collet_children(target_node)
        return nodes_to_reenctypt
    
    def reencrypt_nodes(self, target_node):
        #指定された対象ノードと子孫ノードを収集
        nodes_to_reencrypt = self.find_nodes_to_reencrypt(target_node)

        #各ノードに対して新しい鍵を生成し、再暗号化
        for node in nodes_to_reencrypt:

            #ノードがファイルの場合復号化
            if isinstance(node, File):
                decrypted_data = node.decrypt_data(node.data)
                decrypted_metadata = node.decrypt_metadata(node.metadata)

                #新しい鍵を生成
                node.DKf = Fernet.generate_key()
                node.BKf = Fernet.generate_key()
                node.SKf = Fernet.generate_key()
                node.FKf = Fernet.generate_key()
                node.CKf = Fernet.generate_key()

                #新しい鍵でデータとメタデータを再暗号化
                encrypted_data = node.encrypt_data(decrypted_data)
                encrypted_metadata = node.encrypt_metadata(decrypted_metadata)

                #新しい暗号化されたデータとメタデータを保存
                node.data = encrypted_data
                node.metadata = encrypted_metadata

            elif isinstance(node, Folder):
                # フォルダのメタデータの復号化
                f = Fernet(node.SKf)
                decrypted_metadata = node.decrypt_metadata(node.metadata)

                node.DKf = Fernet.generate_key()
                node.BKf = Fernet.generate_key()
                new_SKf = Fernet.generate_key()
                node.FKf = Fernet.generate_key()
                node.CKf = Fernet.generate_key()

                #子ノードに新しいSKfを適用
                node.SKf = Fernet.generate_key()

                #新しい鍵でメタデータを再暗号化
                f = Fernet(new_SKf)
                encrypted_metadata = f.encrypt(json.dumps(decrypted_metadata).encode())
                node.metadata = encrypted_metadata

                # 子ノードに新しい SKf を適用
                node.SKf = new_SKf
                for child_folder in node.folders:
                    child_folder.SKf = new_SKf
                for child_file in node.files:
                    child_file.SKf = new_SKf

class User:
    def __init__(self, name):
        self.name = name
        self.keys = {}


class File(CryptTree):
    def __init__(self, name, data, parent=None, location_uri=None, filename=None):
        super().__init__(name, parent,location_uri=location_uri,filename=filename)
        self.data = data
        self.metadata = self.encrypt_metadata()
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
    
    def decrypt_metadata(self, encrypted_metadata):
        #print("Encrypted metadata:", encrypted_metadata)

        f = Fernet(self.FKf)
        decrypted_metadata_json = f.decrypt(encrypted_metadata)
        return json.loads(decrypted_metadata_json.decode())


class Folder(CryptTree):
    def __init__(self, name, parent=None):
        super().__init__(name, parent)
        self.files = []
        self.folders = []
        self.child_bkfs = {}
        self.metadata = self.encrypt_metadata()

    def add_file(self, file):
        self.files.append(file)
        file.parent = self
        file.BKf = Fernet.generate_key()
        file.SKf = self.SKf
        file.FKf = self.FKf
        file.encrypted_parent_name = self.encrypt_parent_name()

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
        folder.encrypted_parent_name = self.encrypt_parent_name()

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
        print("SKf in decrypt_metadata:", self.SKf)
        f = Fernet(self.SKf)
        encrypted_metadata = f.encrypt(metadata_json)
        return encrypted_metadata
    
    def decrypt_metadata(self, encrypted_metadata):
        print("SKf in encrypt_metadata:", self.SKf)
        print("Encrypted metadata in decrypt_metadata:", encrypted_metadata)
        f = Fernet(self.SKf)
        decrypted_metadata_json = f.decrypt(encrypted_metadata)
        return json.loads(decrypted_metadata_json.decode())

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

    """# ファイルの暗号化と復号化のテスト
    encrypted_data = file1.encrypt_data()
    print("Encrypted data:", encrypted_data)
    decrypted_data = file1.decrypt_data(encrypted_data)
    print("Decrypted data:", decrypted_data)
    #ファイルメタデータの暗号化・復号化テスト
    encrypted_file_metadata = file1.encrypt_metadata()
    decrypted_file_metadata = file1.decrypt_metadata(encrypted_file_metadata)
    print("File metadata", decrypted_file_metadata) #期待されるメタデータと一致するか

    #フォルダメタデータの暗号化・復号化テスト
    encrypted_folder_metadata = folder1.encrypt_metadata()
    decrypted_folder_metadata = folder1.decrypt_metadata(encrypted_folder_metadata)
    print("Folder metadata:", decrypted_folder_metadata)  # 期待されるメタデータと一致するか確認"""

    """#ファイルから親フォルダの名前を復号化して取得するテスト
    encrypted_parent_name = file1.encrypt_parent_name()
    if encrypted_parent_name:
        decrypted_parent_name = file1.decrypt_parent_name(file1.encrypt_parent_name())
        print("Decrypted parent folder name for FIle1:", decrypted_parent_name)
    else:
        print("File1 has no parent folder.")

        print("\n--- Reencryption Test ---")"""

    # フォルダ1にアクセス権を付与
    folder1.grant_access(user1)
    print("Granted access to Folder1 for User1.")

    # フォルダ1のデータとメタデータを再暗号化
    folder1.reencrypt_nodes(folder1)
    print("Reencrypted data and metadata for Folder1 and its descendants.")

    # 再暗号化後のデータとメタデータを確認
    encrypted_data = file1.data  # 既に暗号化されている
    decrypted_data = file1.decrypt_data(encrypted_data)
    print("Decrypted data after reencryption:", decrypted_data)

    encrypted_metadata = file1.metadata  # 既に暗号化されている
    decrypted_metadata = file1.decrypt_metadata(encrypted_metadata)
    print("Decrypted metadata after reencryption:", decrypted_metadata)

if __name__ == "__main__":
    main()