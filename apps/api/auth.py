import json, os, secrets
from json import JSONDecodeError
from .config import NONCES_PATH
from .crypto import ecdsa_sign, ecdsa_verify

def _load_nonces():
    if not os.path.exists(NONCES_PATH):
        return {}
    try:
        with open(NONCES_PATH, "r", encoding="utf-8") as f:
            txt = f.read().strip()
            if not txt:
                return {}
            return json.loads(txt)
    except (JSONDecodeError, OSError):
        # Jika file rusak/kosong, fallback aman
        return {}

def _save_nonces(n):
    with open(NONCES_PATH, "w") as f:
        json.dump(n, f)

def new_nonce():
    n = _load_nonces()
    nonce = secrets.token_hex(16)
    n[nonce] = True
    _save_nonces(n)
    return nonce

def verify_nonce(nonce: str):
    n = _load_nonces()
    if n.get(nonce):
        del n[nonce]
        _save_nonces(n)
        return True
    return False
