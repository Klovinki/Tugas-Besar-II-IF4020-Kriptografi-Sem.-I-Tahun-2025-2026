from fastapi import FastAPI, Request, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse

import uuid, time, base64, urllib.parse

from .crypto import *
from .ledger import *
from .storage import *
from .auth import *
from .config import STORAGE_DIR

import os

# Memuat Public Key Institusi yang Sah (Hardcoded/Trusted)
# Pastikan file admin_public.pem ada di root direktori (sejajar dengan main.py dijalankan)
try:
    with open("admin_public.pem", "r") as f:
        TRUSTED_ISSUER_PUBKEY = f.read().strip()
except FileNotFoundError:
    print("WARNING: admin_public.pem tidak ditemukan. Validasi issuer tidak akan berjalan!")
    TRUSTED_ISSUER_PUBKEY = None

app = FastAPI()
templates = Jinja2Templates(directory="apps/api/templates")

ADMIN_SESSION = {"ok": False, "pubkey": None, "privkey": None}

@app.get("/", response_class=HTMLResponse)
def index(req: Request):
    return templates.TemplateResponse("index.html", {"request": req})

@app.get("/ledger", response_class=HTMLResponse)
def ledger_page(req: Request):
    txs = load_all()
    ok, bad = verify_chain()
    return templates.TemplateResponse("ledger.html", {
        "request": req, "txs": txs, "ok": ok, "bad": bad
    })

@app.get("/storage/{file_id}")
def storage_get(file_id: str):
    return FileResponse(f"{STORAGE_DIR}/{file_id}")

# -------- Admin --------
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login(req: Request):
    nonce = new_nonce()
    return templates.TemplateResponse("admin_login.html", {"request": req, "nonce": nonce})

@app.post("/admin/login", response_class=HTMLResponse)
def admin_login_post(req: Request, privkey_pem: str = Form(...), nonce: str = Form(...)):
    # nonce harus one-time; kalau invalid, tampilkan error dan generate nonce baru
    if not verify_nonce(nonce):
        new = new_nonce()
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": req, "nonce": new, "error": "Nonce tidak valid/expired. Refresh halaman dan coba lagi."},
            status_code=400
        )

    # Pastikan key tidak kosong
    if not privkey_pem.strip():
        new = new_nonce()
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": req, "nonce": new, "error": "Private key masih kosong. Paste admin_private.pem."},
            status_code=400
        )

    # Sign + verify
    try:
        sig = ecdsa_sign(privkey_pem, nonce.encode())
        pub = load_private_key_pem(privkey_pem).public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        if not ecdsa_verify(pub_pem, nonce.encode(), sig):
            raise ValueError("Signature verify failed")
    except Exception as e:
        new = new_nonce()
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": req, "nonce": new, "error": f"Login gagal: {e}"},
            status_code=400
        )

    ADMIN_SESSION.update({"ok": True, "pubkey": pub_pem, "privkey": privkey_pem})
    return RedirectResponse(url="/admin/issue", status_code=303)


@app.get("/admin/issue", response_class=HTMLResponse)
def admin_issue(req: Request):
    return templates.TemplateResponse("admin_issue.html", {"request": req})

@app.post("/admin/issue")
async def admin_issue_post(file: UploadFile):
    assert ADMIN_SESSION["ok"]
    raw = await file.read()
    doc_hash = sha256_hex(raw)
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce, ct = aes_gcm_encrypt(aes_key, raw)
    file_url, file_id = save_ciphertext(ct)

    cert_id = uuid.uuid4().hex
    ts = int(time.time())
    msg = f"TYPE=ISSUE|CERT_ID={cert_id}|DOC_HASH={doc_hash}|FILE_URL={file_url}|NONCE_GCM={base64.b64encode(nonce).decode()}|TS={ts}".encode()
    sig = ecdsa_sign(ADMIN_SESSION["privkey"], msg)

    tx_data = {
        "type": "ISSUE",
        "timestamp": ts,
        "payload": {
            "cert_id": cert_id,
            "doc_hash_sha256_hex": doc_hash,
            "file_url": file_url,
            "aes_gcm_nonce_b64": base64.b64encode(nonce).decode()
        },
        "issuer_pubkey_pem": ADMIN_SESSION["pubkey"],
        "issuer_signature_hex": sig
    }
    tx_hash = append_tx(tx_data)

    key_b64 = base64.b64encode(aes_key).decode()
    unlisted = f"/v?tx={tx_hash}&file={urllib.parse.quote(file_url)}&key={urllib.parse.quote(key_b64)}"
    return {"unlisted_url": unlisted}

@app.get("/admin/revoke", response_class=HTMLResponse)
def admin_revoke(req: Request):
    return templates.TemplateResponse("admin_revoke.html", {"request": req})

@app.post("/admin/revoke")
def admin_revoke_post(cert_id: str = Form(...), reason: str = Form(...)):
    assert ADMIN_SESSION["ok"]
    ts = int(time.time())
    msg = f"TYPE=REVOKE|CERT_ID={cert_id}|REASON={reason}|TS={ts}".encode()
    sig = ecdsa_sign(ADMIN_SESSION["privkey"], msg)
    tx_data = {
        "type": "REVOKE",
        "timestamp": ts,
        "payload": {"cert_id": cert_id, "reason": reason},
        "issuer_pubkey_pem": ADMIN_SESSION["pubkey"],
        "issuer_signature_hex": sig
    }
    return {"tx_hash": append_tx(tx_data)}

# -------- Verify --------
@app.get("/v", response_class=HTMLResponse)
def verify(req: Request, tx: str, file: str, key: str):
    issue = get_tx(tx)
    if not issue:
        return {"error": "tx not found"}
    
    p = issue["tx_data"]["payload"]
    
    # 1. Cek apakah Issuer adalah Institusi yang Sah
    tx_pubkey = issue["tx_data"].get("issuer_pubkey_pem", "").strip()
    is_trusted_issuer = (tx_pubkey == TRUSTED_ISSUER_PUBKEY)

    # 2. Dekripsi File
    try:
        ct = read_ciphertext(file.split("/")[-1])
        pt = aes_gcm_decrypt(base64.b64decode(key), base64.b64decode(p["aes_gcm_nonce_b64"]), ct)
        text_content = pt.decode() # Asumsi file teks
    except Exception:
        return templates.TemplateResponse("verify.html", {
            "request": req, "valid": False, "revoked": False, "text": "Gagal dekripsi", "error": "Kunci salah atau file rusak"
        })

    # 3. Verifikasi Hash
    ok_hash = sha256_hex(pt) == p["doc_hash_sha256_hex"]
    
    # 4. Cek Revokasi
    revoked = is_revoked(p["cert_id"])
    
    # Status Valid hanya jika: Hash OK + Tidak Revoked + Issuer Sah
    is_valid = ok_hash and not revoked and is_trusted_issuer

    return templates.TemplateResponse("verify.html", {
        "request": req, 
        "valid": is_valid,
        "revoked": revoked,
        "trusted_issuer": is_trusted_issuer, # Kirim status issuer ke template untuk info detail
        "text": text_content,
        "verify_url": str(req.url) # Kirim URL saat ini ke template untuk fitur download
    })