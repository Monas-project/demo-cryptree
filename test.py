import unittest
import json
from cryptree import CryptTreeNode
from fakeIPFS import FakeIPFS

class TestCryptTreeNode(unittest.TestCase):
  def setUp(self):
    #テスト前に実行されるセットアップメソッド
    self.ipfs = FakeIPFS()

    #ディレクトリ構造の作成
    self.root_node = CryptTreeNode.create_node("Root_folder", "owner_id", True, self.ipfs)
    self.sub_folder1 = CryptTreeNode.create_node("Sub_folder1", "owner_id", True, self.ipfs, parent=self.root_node)
    self.sub_folder2 = CryptTreeNode.create_node("Sub_folder2", "owner_id", True, self.ipfs, parent=self.sub_folder1)
    self.sub_folder3 = CryptTreeNode.create_node("Sub_folder3", "owner_id", True, self.ipfs, parent=self.sub_folder2)
    self.file1 = CryptTreeNode.create_node("file1", "owner_id", False, self.ipfs, parent=self.sub_folder3, file_data=b"File content")
    self.sub_folder3.add_node(self.file1.metadata["file_cid"], "file1", "/path/to/file1", False)

    #CIDを取得し、メタデータに設定
    sub_folder1_cid = self.ipfs.add(json.dumps(self.sub_folder1.metadata).encode())
    sub_folder2_cid = self.ipfs.add(json.dumps(self.sub_folder2.metadata).encode())
    sub_folder3_cid = self.ipfs.add(json.dumps(self.sub_folder3.metadata).encode())
    file1_cid = self.ipfs.add(json.dumps(self.file1.metadata).encode())


    #メタデータにCIDを設定
    self.root_node.metadata["child"]["Sub_folder1"] = {"metadata_cid": sub_folder1_cid}
    self.sub_folder1.metadata["child"]["Sub_folder2"] = {"metadata_cid": sub_folder2_cid}
    self.sub_folder2.metadata["child"]["Sub_folder3"] = {"metadata_cid": sub_folder3_cid}

    print("Root Node Metadata:", self.root_node.metadata)
    print("Sub Folder 1 Metadata:", self.sub_folder1.metadata)
    print("Sub Folder 2 Metadata:", self.sub_folder2.metadata)
    print("Sub Folder 3 Metadata:", self.sub_folder3.metadata)
    print("File 1 Metadata:", self.file1.metadata)

    print("setUpが実行されました")
  
  def test_find_deepest_node(self):
    #find_deepest_nodeのテスト
    deepest_node = self.root_node.find_deepest_node()
    self.assertEqual(deepest_node.metadata["name"], "file1" )


if __name__ == '__main__':
  unittest.main()