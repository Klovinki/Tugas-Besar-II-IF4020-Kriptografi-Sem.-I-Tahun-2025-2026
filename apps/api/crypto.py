import base64, json, hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce untuk GCM
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def load_private_key_pem(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)

def load_public_key_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def ecdsa_sign(privkey_pem: str, message: bytes) -> str:
    priv = load_private_key_pem(privkey_pem)
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return sig.hex()

def ecdsa_verify(pubkey_pem: str, message: bytes, sig_hex: str) -> bool:
    pub = load_public_key_pem(pubkey_pem)
    try:
        pub.verify(bytes.fromhex(sig_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
