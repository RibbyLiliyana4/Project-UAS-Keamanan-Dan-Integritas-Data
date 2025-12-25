from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict
import json
import os
import secrets
import hashlib
from datetime import datetime
import binascii

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

DATA_FOLDER = "user-keys"
USERS_FILE = os.path.join(DATA_FOLDER, "users.json")

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

tags_metadata = [
    {"name": "Public", "description": "Akses Publik"},
    {"name": "Secure", "description": "Area Terbatas (Butuh Token)"},
]

app = FastAPI(
    title="Punk Records API",
    version="5.0.0-FIXED",
    description="mugiwara.",
    openapi_tags=tags_metadata
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def load_users_db():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users_db(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def format_pem_automatically(raw_key: str) -> bytes:
    # Bersihkan header/footer manual jika ada
    clean = raw_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
    # Hapus semua whitespace (spasi, enter, tab, dll)
    clean = "".join(clean.split())
    
    # Potong menjadi baris 64 karakter (Standar PEM)
    chunk_size = 64
    chunks = [clean[i:i+chunk_size] for i in range(0, len(clean), chunk_size)]
    body = "\n".join(chunks)
    
    # Bungkus kembali dengan header
    formatted_pem = f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"
    return formatted_pem.encode('utf-8')

active_sessions: Dict[str, str] = {}
user_public_keys: Dict[str, str] = {}
user_inboxes: Dict[str, List[dict]] = {}

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    username = active_sessions.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="Token Invalid/Expired.")
    return username

@app.get("/health", tags=["Public"])
async def health_check():
    return {"status": "ok", "ready": True}

@app.get("/", tags=["Public"])
async def index():
    return {"message": "Server Ready."}

@app.post("/register", tags=["Public"])
async def register(username: str = Form(...), password: str = Form(...)):
    db = load_users_db()
    u = username.lower()
    if u in db:
        raise HTTPException(status_code=400, detail="Username taken.")
    db[u] = {"password": password, "full_name": username.capitalize()}
    save_users_db(db)
    if u not in user_inboxes: user_inboxes[u] = []
    return {"message": f"User {u} registered."}

@app.post("/login", tags=["Public"])
async def login(username: str = Form(...), password: str = Form(...)):
    db = load_users_db()
    u = username.lower()
    if u not in db or db[u]["password"] != password:
        raise HTTPException(status_code=400, detail="Username/Password Salah.")
    token = secrets.token_hex(16)
    active_sessions[token] = u
    return {"access_token": token, "token_type": "Bearer"}

@app.post("/store", tags=["Secure"])
async def store_key(
    public_key_pem: str = Form(..., description="Paste kode Public Key (boleh 1 baris saja)"),
    current_user: str = Depends(verify_token)
):
    try:
        pem_bytes = format_pem_automatically(public_key_pem)
        serialization.load_pem_public_key(pem_bytes)
        user_public_keys[current_user] = pem_bytes.decode('utf-8')
        return {"message": f"Public Key {current_user} berhasil disimpan."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Format Key Salah: {str(e)}")

@app.post("/verify", tags=["Secure"])
async def verify_signature(
    username: str = Form(...),
    message: str = Form(...),
    signature_hex: str = Form(...),
    current_user: str = Depends(verify_token)
):
    target = username.lower()
    if target not in user_public_keys:
        raise HTTPException(status_code=404, detail="User belum setor key.")
    
    try:
        pem_bytes = user_public_keys[target].encode('utf-8')
        public_key = serialization.load_pem_public_key(pem_bytes)
        sig_bytes = binascii.unhexlify(signature_hex)
        
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(sig_bytes, message.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(sig_bytes, message.encode('utf-8'))
            
        return {"status": "VALID", "detail": "Signature OK."}
    except:
        raise HTTPException(status_code=400, detail="Signature INVALID.")

@app.post("/upload-pdf", tags=["Secure"])
async def upload_pdf(file: UploadFile = File(...), current_user: str = Depends(verify_token)):
    content = await file.read()
    pdf_hash = hashlib.sha256(content).hexdigest()
    return {"filename": file.filename, "sha256_hash": pdf_hash}

@app.post("/verify-pdf", tags=["Secure"])
async def verify_pdf(
    username: str = Form(...),
    pdf_hash: str = Form(...),
    signature_hex: str = Form(...),
    current_user: str = Depends(verify_token)
):
    target = username.lower()
    if target not in user_public_keys:
        raise HTTPException(status_code=404, detail="Key missing.")
    try:
        public_key = serialization.load_pem_public_key(user_public_keys[target].encode('utf-8'))
        sig_bytes = binascii.unhexlify(signature_hex)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(sig_bytes, pdf_hash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(sig_bytes, pdf_hash.encode('utf-8'))
        return {"status": "VALID", "detail": "PDF Verified."}
    except:
        raise HTTPException(status_code=400, detail="PDF INVALID.")

@app.post("/relay", tags=["Secure"])
async def relay(
    recipient_username: str = Form(...),
    encrypted_message: str = Form(...),
    current_user: str = Depends(verify_token)
):
    tgt = recipient_username.lower()
    if tgt not in load_users_db(): raise HTTPException(404, "User not found")
    if tgt not in user_inboxes: user_inboxes[tgt] = []
    
    user_inboxes[tgt].append({
        "from": current_user,
        "time": datetime.now().isoformat(),
        "content": encrypted_message
    })
    return {"message": "Sent."}

@app.get("/inbox", tags=["Secure"])
async def inbox(current_user: str = Depends(verify_token)):
    return {"data": user_inboxes.get(current_user, [])}