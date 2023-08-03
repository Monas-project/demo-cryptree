# import os
from cryptography.fernet import Fernet


class CryptTree:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.DKf = Fernet.generate_key()  # Data Key
        self.BKf = Fernet.generate_key()  # Backlink Key
        self.SKf = Fernet.generate_key()  # Subfolder Key
        self.FKf = Fernet.generate_key()  # File Key
        self.CKf = Fernet.generate_key()  # Clearance Key (Optional)
        self.accessors = {}  # Users who can access this node

        if parent:
            # If this node has a parent, link all keys to the parent's keys
            self.BKf = parent.BKf
            self.SKf = parent.SKf
            self.FKf = parent.FKf
            self.CKf = parent.CKf

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
    def __init__(self, name, data, parent=None):
        super().__init__(name, parent)
        self.data = data

    def encrypt_data(self):
        f = Fernet(self.DKf)
        encrypted_data = f.encrypt(self.data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        f = Fernet(self.DKf)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data


class Folder(CryptTree):
    def __init__(self, name, parent=None):
        super().__init__(name, parent)
        self.files = []
        self.folders = []

    def add_file(self, file):
        self.files.append(file)
        file.parent = self
        file.BKf = self.BKf
        file.CKf = self.CKf

    def add_folder(self, folder):
        self.folders.append(folder)
        folder.parent = self
        folder.BKf = self.BKf
        folder.CKf = self.CKf

# テスト用の関数


def main():
    user1 = User("User1")
    user2 = User("User2")

    root_folder = Folder("Root")
    folder1 = Folder("Folder1", parent=root_folder)
    file1 = File("File1", "Data of File1", parent=folder1)
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
