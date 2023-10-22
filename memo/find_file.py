# import os
from cryptography.fernet import Fernet


class CryptTree:
    # 他のコードは省略...

    def find_file(self, filename):
        for file in self.files:
            if file.name == filename:
                return file
        for folder in self.folders:
            found_file = folder.find_file(filename)
            if found_file:
                return found_file
        return None

    def find_file_recursive(self, filename):
        return self._find_file_recursive(self, filename)

    def _find_file_recursive(self, node, filename):
        if isinstance(node, File):
            if node.name == filename:
                return node
        elif isinstance(node, Folder):
            for file in node.files:
                if file.name == filename:
                    return file
            for folder in node.folders:
                found_file = self._find_file_recursive(folder, filename)
                if found_file:
                    return found_file
        return None

# 新しいテスト用の関数


def test_encryption_and_decryption():
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

    # ユーザーがファイルを見つけて暗号化する
    target_filename = "File1"
    found_file = root_folder.find_file(target_filename)
    if found_file:
        encrypted_data = found_file.encrypt_data()
        print("Encrypted data of File1:", encrypted_data)
    else:
        print(f"File '{target_filename}' not found.")

    # 特定のユーザーに対してファイルを見つけて復号化する
    target_filename = "File2"
    found_file = root_folder.find_file(target_filename)
    if found_file:
        target_user = user2
        if target_user.name in found_file.accessors:
            encrypted_data = found_file.data  # 仮の暗号化されたデータ
            f = Fernet(target_user.keys[found_file.name])
            decrypted_data = f.decrypt(encrypted_data.encode()).decode()
            print(
                f"Decrypted data of File2 for {target_user.name}: {decrypted_data}")
        else:
            print(f"User '{target_user.name}' does not have access to File2.")
    else:
        print(f"File '{target_filename}' not found.")

    # ツリー全体を探索してファイルを見つける
    target_filename = "File2"
    found_file = root_folder.find_file_recursive(target_filename)
    if found_file:
        print(f"File '{target_filename}' found in the tree.")
    else:
        print(f"File '{target_filename}' not found in the tree.")


if __name__ == "__main__":
    test_encryption_and_decryption()
