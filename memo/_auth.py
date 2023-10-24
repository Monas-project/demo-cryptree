import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from memo.did import DID, PRIVATE_KEY
from cryptography.exceptions import InvalidSignature
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519


# ランダムな認証チャレンジを生成
def generate_challenge():
    challenge = os.urandom(32).hex()
    return challenge


def sign_challenge(challenge, private_key):

    # challenge（サーバーから受け取ったもの）
    challenge_received = bytes.fromhex(challenge)
    signature = private_key.sign(challenge_received)
    # 署名を16進数形式に変換（送信のため）
    return signature.hex()


def get_public_key_from_did(did):
    # DIDから公開鍵を取得
    public_key_bytes = base58.b58decode(did.split(":")[-1])[2:]
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)


def verify_signature(did, signature, challenge):
    # 受け取った署名をバイト形式に変換
    public_key = get_public_key_from_did(did)
    received_signature = bytes.fromhex(signature)
    try:
        public_key.verify(received_signature, bytes.fromhex(challenge))
        return True
    except InvalidSignature:
        return False
