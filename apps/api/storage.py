import os, uuid
from .config import STORAGE_DIR, HOST_URL

def save_ciphertext(data: bytes) -> str:
    file_id = f"{uuid.uuid4().hex}.bin"
    path = os.path.join(STORAGE_DIR, file_id)
    with open(path, "wb") as f:
        f.write(data)
    return f"{HOST_URL}/storage/{file_id}", file_id

def read_ciphertext(file_id: str) -> bytes:
    path = os.path.join(STORAGE_DIR, file_id)
    with open(path, "rb") as f:
        return f.read()
