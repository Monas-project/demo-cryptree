from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base58

# 鍵ペアの生成
private_key = ed25519.Ed25519PrivateKey.generate()

# 公開鍵をバイト形式に変換
public_key_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Ed25519のマルチコーデックプレフィックス
ed25519_prefix = bytes.fromhex('ed01')

# プレフィックスと公開鍵を結合
ed25519_public_key = ed25519_prefix + public_key_bytes

# Base58エンコード
encoded_key = base58.b58encode(ed25519_public_key)  # ここをb58encodeに変更

# DIDの形成
did_key_manual = f'did:key:{encoded_key.decode()}'

print(did_key_manual)

# DID Documentの定義
did_document = {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": did_key_manual,
    "publicKey": [
        {
            "id": f"{did_key_manual}#primary",
            "type": "Ed25519VerificationKey2018",
            "controller": did_key_manual,
            "publicKeyBase58": encoded_key.decode()
        }
    ],
    "authentication": [
        f"{did_key_manual}#primary"
    ]
}

# DID Documentの表示
did_document

DID = did_key_manual
PRIVATE_KEY = private_key