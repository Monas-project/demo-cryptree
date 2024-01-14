from fastapi.testclient import TestClient
from main import app
import unittest

class FileSystemAPITestCase(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_upload_and_fetch_folders(self):
        # フォルダのアップロード
        response = self.client.post("/upload", data={
            "name": "Folder1",
            "id": "test",
            "path": "/folder1",
            "isDirectory": True
        })
        self.assertEqual(response.status_code, 200)

        response = self.client.post("/upload", data={
            "name": "Folder2",
            "id": "test",
            "path": "/folder2",
            "isDirectory": True
        })
        self.assertEqual(response.status_code, 200)

        print()
        print("---- read folder data -----")

        # アップロードされたフォルダの確認
        response = self.client.post("/fetch", json={"path": "/folder1"})
        self.assertEqual(response.status_code, 200)
        print("response1",response.json())

        response = self.client.post("/fetch", json={"path": "/folder2"})
        self.assertEqual(response.status_code, 200)
        print("response2",response.json())
        

if __name__ == "__main__":
    unittest.main()
