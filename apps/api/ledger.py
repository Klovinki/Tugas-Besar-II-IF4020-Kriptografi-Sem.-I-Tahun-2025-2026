import json, os
from .config import LEDGER_PATH
from .crypto import sha256_hex, canonical_json

GENESIS = "00" * 32

def _ensure_ledger():
    if not os.path.exists(LEDGER_PATH):
        open(LEDGER_PATH, "w").close()

def load_all():
    _ensure_ledger()
    txs = []
    with open(LEDGER_PATH, "r") as f:
        for line in f:
            if line.strip():
                txs.append(json.loads(line))
    return txs

def append_tx(tx_data: dict) -> str:
    txs = load_all()
    prev = txs[-1]["tx_hash"] if txs else GENESIS
    payload = {
        "prev_hash": prev,
        "tx_data": tx_data
    }
    tx_hash = sha256_hex(canonical_json(payload))
    record = {
        "tx_hash": tx_hash,
        "prev_hash": prev,
        "tx_data": tx_data
    }
    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")
    return tx_hash

def get_tx(tx_hash: str):
    for tx in load_all():
        if tx["tx_hash"] == tx_hash:
            return tx
    return None

def verify_chain():
    txs = load_all()
    prev = GENESIS
    for i, tx in enumerate(txs):
        payload = {"prev_hash": prev, "tx_data": tx["tx_data"]}
        expect = sha256_hex(canonical_json(payload))
        if expect != tx["tx_hash"] or tx["prev_hash"] != prev:
            return False, i
        prev = tx["tx_hash"]
    return True, None

def is_revoked(cert_id: str):
    for tx in load_all():
        if tx["tx_data"]["type"] == "REVOKE":
            if tx["tx_data"]["payload"]["cert_id"] == cert_id:
                return True
    return False
