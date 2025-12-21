import os

ROOT_DIR = os.path.abspath(os.getcwd())

DATA_DIR = os.path.join(ROOT_DIR, "data")
STORAGE_DIR = os.path.join(ROOT_DIR, "storage")

LEDGER_PATH = os.path.join(DATA_DIR, "ledger.jsonl")
NONCES_PATH = os.path.join(DATA_DIR, "nonces.json")

HOST_URL = "http://127.0.0.1:8000"
