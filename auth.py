import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from did import DID, PRIVATE_KEY
from cryptography.exceptions import InvalidSignature
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519


# ランダムな認証チャレンジを生成
challenge = os.urandom(32).hex()  # ここを修正

print(challenge) # クライアントに送信する

# challenge（サーバーから受け取ったもの）
challenge_received = bytes.fromhex(challenge)

# challengeに対して秘密鍵で署名
signature = PRIVATE_KEY.sign(challenge_received)

# 署名を16進数形式に変換（送信のため）
signature_hex = signature.hex()

# サーバーに送信する認証応答
auth_response = {
    "did": DID,  # ここを修正
    "signature": signature_hex
}

print(auth_response)

received_auth_response = auth_response  # ここでは例として同じ値を使用

# DIDから公開鍵を取得
public_key_bytes = base58.b58decode(DID.split(":")[-1])[2:]
public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

# 受け取った署名をバイト形式に変換
received_signature = bytes.fromhex(received_auth_response["signature"])

# 署名の検証
try:
    public_key.verify(received_signature, challenge_received)
    print("Authentication successful!")
except InvalidSignature:
    print("Authentication failed!")