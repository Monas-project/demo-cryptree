# import os
from cryptography.fernet import Fernet
import json
from auth import DID, generate_challenge, sign_challenge, verify_signature, PRIVATE_KEY

class KeyStorage:
    def __init__(self):
        self.storege = {}
    
    def store_key(self, key_name, key_value):
        self.storege[key_name] = key_value
    
    def retrieve_key(self, key_name):
        return self.storege.get(key_name)

class CryptTree:
    def __init__(self, name, controller_did, parent=None, location_uri=None,filename=None):
        self.name = name
        self.controller_did = controller_did # cryptreeを制御するDID
        self.authenticated_did = None
        self.parent = None
        self.location_uri = location_uri
        self.filename = filename
        self.key_storage = KeyStorage() #Keytorageのインスタンスを保存
        self.accessors = {}  # Users who can access this node

        if parent:
            self.parent = parent
            # Inherit all keys except BKf from parent
            self.BKf = Fernet.generate_key()
            self.SKf = parent.SKf
            self.CKf = parent.CKf
        else:
            self.BKf = Fernet.generate_key() # Backlink Key
            self.SKf = Fernet.generate_key() # Subfolder Key
            self.CKf = Fernet.generate_key() # Clearance Key (Optional)

    def request_access(self):
        #チャレンジを生成
        challenge = generate_challenge()

        user_signature = sign_challenge(challenge, PRIVATE_KEY)

        #署名を検証
        if verify_signature(self.controller_did, user_signature, challenge):
            self.authenticated_did = self.controller_did
            print("Authentication successful!")

        else:
            self.authenticated_did = None
            print("Authentication failed!")


    def store_my_keys(self):
        #ファイルの場合
        if isinstance(self, File):
            #DKf
            data_key_name = f"{self.name}_data_DKf"
            self.key_storage.store_key(data_key_name, self.DKf)

            #FKf
            metadata_key_name = f"{self.name}_metadata_FKf"
            self.key_storage.store_key(metadata_key_name, self.FKf)

        #Folderの場合
        elif isinstance(self, Folder):
            #SFK
            subfolder_key_name = f"{self.name}_SKf"
            self.key_storage.store_key(subfolder_key_name, self.SKf)

    def retrieve_my_keys(self):
        # ファイルの場合
        if isinstance(self, File):
            data_key_name = f"{self.name}_data_DKf"
            metadata_key_name = f"{self.name}_metadata_FKf"
            return self.key_storage.retrieve_key(data_key_name), self.key_storage.retrieve_key(metadata_key_name)
    
    # フォルダの場合
        elif isinstance(self, Folder):
            #SKf
            subfolder_key_name = f"{self.name}_SKf"
            return self.key_storage.retrieve_key(subfolder_key_name)


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
        nodes_to_reencrypt = [target_node]

        #対象ノードの子孫ノード再帰的に追加(特定ノードとその子孫ノードを全て返す)
        def collect_children(node):
            if isinstance(node, Folder):
                for child_file in node.files:
                    nodes_to_reencrypt.append(child_file)
                    collect_children(child_file) 
                for child_folder in node.folders:
                    nodes_to_reencrypt.append(child_folder)
                    collect_children(child_folder)

        collect_children(target_node)
        return nodes_to_reencrypt
    
    def decrypt_nodes_recursively(self, node):
        #print(f"Files in {node.name}: {[f.name for f in node.files]}")
        #print("decrypt_nodes_from_target called")
        print(f"Node name: {node.name}, Files in node: {[f.name for f in node.files]}")
        if isinstance(node, Folder):
            #print(f"Decrypting metadata for folder: {node.name}...")
            #print(f"Number of subfolders in {node.name}: {len(node.folders)}")
            #print(f"Number of files in {node.name}: {len(node.files)}")
            # まずフォルダのメタデータを復号化
            decrypted_metadata = node.decrypt_metadata(node.metadata)
            node.metadata = decrypted_metadata
        
            # フォルダのサブフォルダとファイルのリストを取得して再帰的に復号化
            for subfolder in node.folders:
                #print(f"Files in folder {node.name} before decryption: {[f.name for f in node.files]}")
                print(f"Processing subfolder {subfolder.name} of {node.name}")
                self.decrypt_nodes_recursively(subfolder)
                #print(f"Files in folder {node.name} before decryption: {[f.name for f in node.files]}")


            for file in node.files:
                print(f"Name: {file.name}, Type: {type(file)}")
                self.decrypt_nodes_recursively(file)
                
        elif isinstance(node, File):
            print(f"Decrypting data and metadata for file: {node.name}...")
        # ファイルのデータとメタデータを復号化
            decrypted_metadata = node.decrypt_metadata(node.metadata)
            decrypted_data = node.decrypt_data(node.data)
            
            node.metadata = decrypted_metadata
            node.data = decrypted_data
            #print(f"Finished decryption for file: {node.name}")

    def reencrypt_nodes(self, target_node):
        #DID認証
        if not self.request_access():
            print("Access denied! Authentication failed.")
            return

        nodes_to_reencrypt = self.find_nodes_to_reencrypt(target_node)

        #最下層から最上層へ順序付けて再暗号化
        for node in reversed(nodes_to_reencrypt):

            #ノードがファイルの場合の処理
            if isinstance(node, File):
            # 1. 現在のキーを使用してデータとメタデータを復号化
                #print("Will Encrypting data:", node.data)
                #print("Will decrypting data with DKf:", node.DKf)
                decrypted_data = node.decrypt_data(node.data)
                #print("Will Encrypting metadata:", node.metadata)
                #print("Will decrypting metadata with FKf:", node.FKf)
                decrypted_metadata = node.decrypt_metadata(node.metadata)
            
                # 2. 新しいキーを生成
                new_DKf = Fernet.generate_key()
                new_FKf = Fernet.generate_key()
                new_BKf = Fernet.generate_key()

                # 3. 新しいキーを使用してデータとメタデータを暗号化
                node.DKf = new_DKf
                node.FKf = new_FKf
                encrypted_data = node.encrypt_data(decrypted_data)
                encrypted_metadata = node.encrypt_metadata(decrypted_metadata)
            
                # 4. ノードに暗号化されたデータとメタデータを保存
                node.data = encrypted_data
                node.metadata = encrypted_metadata
                
            #ノードがFolderの場合の処理
            elif isinstance(node, Folder):
                #print("Will decrypting metadata:", node.metadata)
                #print("Will decrypting metadata with SKf:", node.SKf)
                decrypted_metadata = node.decrypt_metadata(node.metadata)

                new_BKf = Fernet.generate_key()
                new_SKf = Fernet.generate_key()

                node.SKf = new_SKf
                f = Fernet(new_SKf)
                encrypted_metadata = f.encrypt(json.dumps(decrypted_metadata).encode())
                node.metadata = encrypted_metadata
                for child_folder in node.folders:
                    child_folder.SKf = new_SKf

            #共通の処理(BKFの再暗号)
            if node.parent:
                node.BKf = new_BKf
                encrypted_parent_name = Fernet(new_BKf).encrypt(node.parent.name.encode())
                node.encrypted_parent_name = encrypted_parent_name
                node.parent.child_bkfs[node.name] = new_BKf

class User:
    def __init__(self, name):
        self.name = name
        self.keys = {}


class File(CryptTree):
    def __init__(self, name, data, parent=None, location_uri=None, filename=None):
        super().__init__(name, parent, location_uri, filename)
        self.data = self.encrypt_data(data)
        self.metadata = self.encrypt_metadata({"filename": self.filename, "creation_date": "some_date", "location": self.location_uri})
        self.parent_link = None

    def encrypt_data(self, data):
        #DKfが存在しない場合にのみDKfを生成
        if not hasattr(self, "DKf"):
            self.DKf = Fernet.generate_key()

        f = Fernet(self.DKf)
        encrypted_data = f.encrypt(data.encode())
        #print("Encrypted data:", encrypted_data)
        #print("Encrypted data with DKf:", self.DKf)
        return encrypted_data

    def decrypt_data(self, encrypted_data):

        #print("Decrypting data...")

        f = Fernet(self.DKf)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    
    #JSONの暗号化
    def encrypt_metadata(self, metadata):
        #metadataはファイル名、作成日時、保存場所
        metadata_json = json.dumps(metadata).encode()

        # FKfがまだ存在しない場合にのみ、新しいFKfを生成
        if not hasattr(self, "FKf"):
            self.FKf = Fernet.generate_key()

        f = Fernet(self.FKf)
        encrypted_metadata = f.encrypt(metadata_json)
        #print("Encrypted metadata:", encrypted_metadata)
        #print("Encrypted metadata with FKf:", self.FKf)
        return encrypted_metadata
    
    def decrypt_metadata(self, encrypted_metadata):
        print(f"Decrypting metadata for file: {self.name}...")
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
        #print(f"Adding file: {file.name} to folder: {self.name}")
        self.files.append(file)
        file.parent = self
        file.BKf = Fernet.generate_key()
        file.SKf = self.SKf
        file.encrypted_parent_name = self.encrypt_parent_name()

        #子ファイルのBKfを保持
        self.child_bkfs[file.name] = file.BKf

        #BKfで親の名前を隠している
        f = Fernet(self.BKf)
        encrypted_link = f.encrypt(file.name.encode())
        file.parent_link = encrypted_link

        #print(f"Files in folder {self.name}: {[f.name for f in self.files]}")


    def add_folder(self, folder):
        #print(f"Files in folder {self.name}: {[f.name for f in self.files]}")
        self.folders.append(folder)
        folder.parent = self
        folder.BKf = Fernet.generate_key()
        folder.SKf = self.SKf
        folder.encrypted_parent_name = self.encrypt_parent_name()

        #BKfで親の名前を隠している
        f = Fernet(folder.BKf)
        encrypted_link = f.encrypt(folder.name.encode())
        folder.parent_link = encrypted_link

        #print(f"Subfolders in folder {self.name}: {[f.name for f in self.folders]}")

    def encrypt_metadata(self):
        #metadataはフォルダ名、作成日時
        metadata = {
            "foldername": self.name,
            "creation_date": "some_date",
        }

        metadata_json = json.dumps(metadata).encode()
        f = Fernet(self.SKf)
        encrypted_metadata = f.encrypt(metadata_json)
        #print("Encrypted metadata:", encrypted_metadata)
        #print("Encrypted metadata with SKf:", self.SKf)
        return encrypted_metadata
    
    def decrypt_metadata(self, encrypted_metadata):
        #print("Decrypting metadata for folder...")
        f = Fernet(self.SKf)
        decrypted_metadata_json = f.decrypt(encrypted_metadata)
        return json.loads(decrypted_metadata_json.decode())
    


# テスト用の関数

def test_key_storage():
    # 1. KeyStorageのインスタンスを作成
    key_storage = KeyStorage()

    # 2. FileおよびFolderのインスタンスを作成し、KeyStorageインスタンスを関連付け
    file = File("testfile", "testdata")
    file.key_storage = key_storage
    folder = Folder("testfolder")
    folder.key_storage = key_storage

    # 3. 鍵を格納
    file.store_my_keys()
    folder.store_my_keys()

    # 4. 鍵を取得して、それが正しいか確認
    assert file.retrieve_my_keys() == (file.DKf, file.FKf), "File keys retrieval failed"
    assert folder.retrieve_my_keys() == folder.SKf, "Folder key retrieval failed"

    print("All tests passed!")

def test_request_access():
    # CryptTreeのインスタンスを作成
    tree = CryptTree(name="root", controller_did=DID)
    
    # 認証のテスト
    tree.request_access()

def test_decryption_process():
    # Step 1: Create instances and encrypt data and metadata
    root_folder = Folder(name="root_folder")
    sub_folder = Folder(name="sub_folder")
    root_folder.add_folder(sub_folder)
    file1 = File(name="file1", data="This is file data")
    sub_folder.add_file(file1)
    
    # Step 2: Verify that the data and metadata are encrypted
    assert file1.data != "This is file data"
    assert isinstance(file1.metadata, bytes) or "filename" not in file1.metadata
    
    # Step 3: Use decrypt_nodes_recursively to decrypt the specified node and its descendants
    root_folder.decrypt_nodes_recursively(root_folder)
    
    # Step 4: Verify that the decrypted data and metadata match the original data and metadata
    assert file1.data == "This is file data"
    assert file1.metadata["filename"] == file1.filename

"""def test_metadata_encryption_and_decryption():
    file1 = File(name="File1", data="Sample Data")

    encrypted_metadata = file1.metadata

    # メタデータの復号化
    decrypted_metadata = file1.decrypt_metadata(encrypted_metadata)

    # 復号化されたメタデータが正しいか確認
    assert decrypted_metadata == {
        "filename": file1.filename,
        "creation_date": "some_date",
        "location": file1.location_uri
    }
    print("Metadata encryption and decryption test passed!")"""

"""def test_reencryption():
    root_folder = Folder(name="RootFolder")
    sub_folder = Folder(name="SubFolder", parent=root_folder)
    file1 = File(name="File1", data="Sample Data", parent=sub_folder)
    sub_folder.add_file(file1)
    root_folder.add_folder(sub_folder)

    # 再暗号化前のデータとメタデータを取得
    original_data = file1.data
    original_metadata = file1.metadata

    # 再暗号化プロセスを実行
    root_folder.reencrypt_nodes(target_node=root_folder)

    # 再暗号化後のデータとメタデータを取得
    reencrypted_data = file1.data
    reencrypted_metadata = file1.metadata

    # 再暗号化前と後のデータとメタデータが異なることを確認
    assert original_data != reencrypted_data
    assert original_metadata != reencrypted_metadata

    # 再暗号化後のデータとメタデータが正しく復号化できることを確認
    decrypted_data = file1.decrypt_data(reencrypted_data)
    decrypted_metadata = file1.decrypt_metadata(reencrypted_metadata)
    assert decrypted_data == "Sample Data"
    print("Reencryption test passed!")"""

def main():
    #test_metadata_encryption_and_decryption()
    #test_reencryption()
    #test_reencryption_file_only()
    #test_key_storage()
    #test_request_access()
    test_decryption_process()

if __name__ == "__main__":
    main()