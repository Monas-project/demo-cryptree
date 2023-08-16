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
            self.BKf = Fernet.generate_key()
            self.SKf = parent.SKf
            self.CKf = parent.CKf
        else:
            self.BKf = Fernet.generate_key() # Backlink Key
            self.SKf = Fernet.generate_key() # Subfolder Key
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

    def reencrypt_nodes(self, target_node):
        nodes_to_reencrypt = self.find_nodes_to_reencrypt(target_node)

        #最下層から最上層へ順序付けて再暗号化
        for node in reversed(nodes_to_reencrypt):

            #ノードがファイルの場合の処理
            if isinstance(node, File):
            # 1. 現在のキーを使用してデータとメタデータを復号化
                print("Decrypting metadata with FKf:", node.FKf)
                decrypted_data = node.decrypt_data(node.data)
                print("Decrypted metadata:", encrypted_metadata)

                print("Decrypting data with DKf:", node.DKf)
                decrypted_metadata = node.decrypt_metadata(node.metadata)
                print("Decrypted data:", encrypted_data)
            
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
        #メタデータを定義
        metadata = {
            "filename": self.filename,
            "creation_date": "some_date",
            "location": self.location_uri
        }
        self.metadata = self.encrypt_metadata({"filename": self.filename, "creation_date": "some_date", "location": self.location_uri})
        self.parent_link = None

    def encrypt_data(self, data):
        #DKfが存在しない場合にのみDKfを生成
        if not hasattr(self, "DKf"):
            self.DKf = Fernet.generate_key()

        f = Fernet(self.DKf)
        encrypted_data = f.encrypt(data.encode())
        print("Encrypting data with DKf:", self.DKf)
        print("Encrypted data:", encrypted_data)
        return encrypted_data

    def decrypt_data(self, encrypted_data):
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
        print("Encrypting metadatadata with FKf:", self.FKf)
        print("Encrypted metadata:", encrypted_metadata)
        return encrypted_metadata
    
    def decrypt_metadata(self, encrypted_metadata):
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
        #FKfが存在しない場合に生成
        if not hasattr(file, "FKf"):
            file.FKf = self.FKf
        file.encrypted_parent_name = self.encrypt_parent_name()

        #子ファイルのBKfを保持
        self.child_bkfs[file.name] = file.BKf

        #BKfで親の名前を隠している
        f = Fernet(self.BKf)
        encrypted_link = f.encrypt(file.name.encode())
        file.parent_link = encrypted_link

    def add_folder(self, folder):
        # 親フォルダーにFKfがある場合は、それを子フォルダーに設定する
        if hasattr(self, 'FKf'):
            folder.FKf = self.FKf
        self.folders.append(folder)
        folder.parent = self
        folder.BKf = Fernet.generate_key()
        folder.SKf = self.SKf
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
        f = Fernet(self.SKf)
        encrypted_metadata = f.encrypt(metadata_json)
        return encrypted_metadata
    
    def decrypt_metadata(self, encrypted_metadata):
        f = Fernet(self.SKf)
        decrypted_metadata_json = f.decrypt(encrypted_metadata)
        return json.loads(decrypted_metadata_json.decode())

# テスト用の関数

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

def test_reencryption_file_only():
    # ファイルのみを直接作成
    file1 = File(name="File1", data="Sample Data")

    # 再暗号化前のデータとメタデータを取得
    original_data = file1.data
    original_metadata = file1.metadata

    # ファイルに対して再暗号化プロセスを実行
    file1.reencrypt_node()  # この関数はファイルの再暗号化を行うものとして仮定します

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
    print("Reencryption test for file only passed!")

def main():
    """controller_did = "did:key:xyz"
    root_folder = Folder("Root", controller_did)



    #親ノードの暗号化、復号化
    encrypted_parent_name = root_folder.encrypt_parent_name()
    if encrypted_parent_name:
        decrypted_parent_name = root_folder.decrypt_parent_name(encrypted_parent_name)
        print("Decrypted parent folder name for Root:", decrypted_parent_name)
    else:
        print("Root has no parent folder.")

    # Userクラスの初期化
    user1 = User("User1")
    user2 = User("User2")
    
    print("User1's name:", user1.name)  # 期待される出力: "User1"
    print("User2's name:", user2.name)  # 期待される出力: "User2"
    print("User1's keys:", user1.keys)  # 期待される出力: {}
    print("User2's keys:", user2.keys)  # 期待される出力: {}

    # Fileクラスの初期化
    folder1 = Folder("Folder1")
    file1 = File("File1", "Data of File1", parent=folder1, location_uri="ipfs://CID1", filename="document.txt")

    # ファイルデータの暗号化・復号化テスト
    encrypted_data = file1.encrypt_data()
    print("Encrypted data:", encrypted_data)
    decrypted_data = file1.decrypt_data(encrypted_data)
    print("Decrypted data:", decrypted_data)  # 期待される出力: "Data of File1"

    # ファイルメタデータの暗号化・復号化テスト
    encrypted_metadata = file1.encrypt_metadata()
    decrypted_metadata = file1.decrypt_metadata(encrypted_metadata)
    print("File metadata:", decrypted_metadata)  # 期待されるメタデータと一致するか確認

    # Folderクラスの初期化
    folder1 = Folder("Folder1")

    # フォルダメタデータの暗号化・復号化テスト
    encrypted_metadata = folder1.encrypt_metadata()
    decrypted_metadata = folder1.decrypt_metadata(encrypted_metadata)
    print("Folder metadata:", decrypted_metadata)  # 期待されるメタデータと一致するか確認

    # Folderクラスのadd_fileとadd_folderメソッドのテスト
    root_folder = Folder("Root")
    folder1 = Folder("Folder1")
    file1 = File("File1", "Data of File1")

    # フォルダとファイルを追加
    root_folder.add_folder(folder1)
    folder1.add_file(file1)

    # フォルダとファイルが正しく追加されたか確認
    print("Root folder's child folders:", [folder.name for folder in root_folder.folders])  # 期待される出力: ["Folder1"]
    print("Folder1's child files:", [file.name for file in folder1.files])  # 期待される出力: ["File1"]"""

    """user1 = User("User1")
    user2 = User("User2")
    folder1 = Folder("Folder1")

    # アクセス権の付与
    folder1.grant_access(user1)
    print("User1's keys after granting access:", user1.keys)  # 期待される出力: 鍵が含まれるディクショナリ

    # アクセス権の取り消し
    folder1.revoke_access(user1)
    print("User1's keys after revoking access:", user1.keys)  # 期待される出力: 空のディクショナリ"""
    
    """# インスタンスの作成
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
    # 他のメタデータの検証もここで追加できます"""

    #test_metadata_encryption_and_decryption()
    #test_reencryption()
    test_reencryption_file_only()

if __name__ == "__main__":
    main()