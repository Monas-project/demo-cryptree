use rand::Rng;
use std::collections::HashMap;

struct CryptoTree {
    name: String,
    parent: Option<Box<CryptoTree>>,
    dkf: [u8; 32],                    // Data Key
    bkf: [u8; 32],                    // Backlink Key
    skf: [u8; 32],                    // Subfolder Key
    fkf: [u8; 32],                    // File Key
    ckf: [u8; 32],                    // Clearance Key (Optional)
    accessors: HashMap<String, User>, // Users who can access this node
}

impl CryptoTree {
    fn new(name: &str, parent: Option<Box<CryptoTree>>) -> Self {
        CryptoTree {
            name: name.to_string(),
            parent,
            dkf: rand::thread_rng().gen::<[u8; 32]>(),
            bkf: rand::thread_rng().gen::<[u8; 32]>(),
            skf: rand::thread_rng().gen::<[u8; 32]>(),
            fkf: rand::thread_rng().gen::<[u8; 32]>(),
            ckf: rand::thread_rng().gen::<[u8; 32]>(),
            accessors: HashMap::new(),
        }
    }

    fn grant_access(&mut self, user: &mut User) {
        self.accessors.insert(user.name.clone(), user.clone());
        user.keys.insert(self.name.clone(), self.dkf);
    }

    fn revoke_access(&mut self, user: &mut User) {
        if self.accessors.contains_key(&user.name) {
            self.accessors.remove(&user.name);
            user.keys.remove(&self.name);
        }
    }
}

#[derive(Clone)]
struct User {
    name: String,
    keys: HashMap<String, [u8; 32]>,
}

impl User {
    fn new(name: &str) -> Self {
        User {
            name: name.to_string(),
            keys: HashMap::new(),
        }
    }
}

struct File {
    name: String,
    data: String,
    parent: Option<Box<CryptoTree>>,
}

impl File {
    fn new(name: &str, data: &str, parent: Option<Box<CryptoTree>>) -> Self {
        File {
            name: name.to_string(),
            data: data.to_string(),
            parent,
        }
    }

    fn encrypt_data(&self) -> Vec<u8> {
        let cipher = openssl::symm::Cipher::aes_256_cbc();
        let mut encrypted_data =
            openssl::symm::encrypt(cipher, &self.fkf, Some(&[0u8; 16]), self.data.as_bytes())
                .unwrap();
        encrypted_data
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> String {
        let cipher = openssl::symm::Cipher::aes_256_cbc();
        let decrypted_data =
            openssl::symm::decrypt(cipher, &self.fkf, Some(&[0u8; 16]), encrypted_data).unwrap();
        String::from_utf8(decrypted_data).unwrap()
    }
}

struct Folder {
    name: String,
    parent: Option<Box<CryptoTree>>,
    files: Vec<File>,
    folders: Vec<CryptoTree>,
}

impl Folder {
    fn new(name: &str, parent: Option<Box<CryptoTree>>) -> Self {
        Folder {
            name: name.to_string(),
            parent,
            files: Vec::new(),
            folders: Vec::new(),
        }
    }

    fn add_file(&mut self, file: File) {
        self.files.push(file);
    }

    fn add_folder(&mut self, mut folder: CryptoTree) {
        folder.parent = Some(Box::new(CryptoTree::new("", self.parent.clone())));
        folder.bkf = self.bkf;
        folder.ckf = self.ckf;
        self.folders.push(folder);
    }
}

fn main() {
    let mut user1 = User::new("User1");
    let mut user2 = User::new("User2");

    let mut root_folder = Folder::new("Root", None);
    let mut folder1 = Folder::new(
        "Folder1",
        Some(Box::new(CryptoTree::new(
            "",
            Some(Box::new(root_folder.clone())),
        ))),
    );
    let file1 = File::new("File1", "Data of File1", Some(Box::new(folder1.clone())));
    folder1.add_file(file1);
    root_folder.add_folder(folder1);

    let mut folder2 = Folder::new(
        "Folder2",
        Some(Box::new(CryptoTree::new(
            "",
            Some(Box::new(root_folder.clone())),
        ))),
    );
    let file2 = File::new("File2", "Data of File2", Some(Box::new(folder2.clone())));
    folder2.add_file(file2);
    root_folder.add_folder(folder2);

    root_folder.grant_access(&mut user1);
    root_folder.grant_access(&mut user2);

    println!("User1's keys: {:?}", user1.keys);
    println!("User2's keys: {:?}", user2.keys);

    // ファイルの暗号化と復号化のテスト
    let encrypted_data = root_folder.folders[0].files[0].encrypt_data();
    println!("Encrypted data: {:?}", encrypted_data);
    let decrypted_data = root_folder.folders[0].files[0].decrypt_data(&encrypted_data);
    println!("Decrypted data: {:?}", decrypted_data);
}
