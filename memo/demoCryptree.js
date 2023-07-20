const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class CryptoTree {
  constructor(name, parent = null) {
    this.name = name;
    this.parent = parent;
    this.DKf = crypto.randomBytes(32); // Data Key
    this.BKf = crypto.randomBytes(32); // Backlink Key
    this.SKf = crypto.randomBytes(32); // Subfolder Key
    this.FKf = crypto.randomBytes(32); // File Key
    this.CKf = crypto.randomBytes(32); // Clearance Key (Optional)
    this.accessors = {}; // Users who can access this node
  }

  grantAccess(user) {
    this.accessors[user.name] = user;
    user.keys[this.name] = this.DKf;
  }

  revokeAccess(user) {
    if (user.name in this.accessors) {
      delete this.accessors[user.name];
      delete user.keys[this.name];
    }
  }
}

class User {
  constructor(name) {
    this.name = name;
    this.keys = {};
  }
}

class File extends CryptoTree {
  constructor(name, data, parent = null) {
    super(name, parent);
    this.data = data;
  }

  encryptData() {
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      this.FKf,
      Buffer.alloc(16)
    );
    let encryptedData = cipher.update(this.data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    return encryptedData;
  }

  decryptData(encryptedData) {
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      this.FKf,
      Buffer.alloc(16)
    );
    let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
  }
}

class Folder extends CryptoTree {
  constructor(name, parent = null) {
    super(name, parent);
    this.files = [];
    this.folders = [];
  }

  addFile(file) {
    this.files.push(file);
  }

  addFolder(folder) {
    this.folders.push(folder);
    folder.parent = this;
    folder.BKf = this.BKf;
    folder.CKf = this.CKf;
  }
}

// テスト用の関数
function main() {
  const user1 = new User('User1');
  const user2 = new User('User2');

  const rootFolder = new Folder('Root');
  const folder1 = new Folder('Folder1', rootFolder);
  const file1 = new File('File1', 'Data of File1', folder1);
  folder1.addFile(file1);
  rootFolder.addFolder(folder1);

  const folder2 = new Folder('Folder2', rootFolder);
  const file2 = new File('File2', 'Data of File2', folder2);
  folder2.addFile(file2);
  rootFolder.addFolder(folder2);

  folder1.grantAccess(user1);
  folder2.grantAccess(user2);

  console.log("User1's keys:", user1.keys);
  console.log("User2's keys:", user2.keys);

  // ファイルの暗号化と復号化のテスト
  const encryptedData = file1.encryptData();
  console.log('Encrypted data:', encryptedData);
  const decryptedData = file1.decryptData(encryptedData);
  console.log('Decrypted data:', decryptedData);
}

main();
