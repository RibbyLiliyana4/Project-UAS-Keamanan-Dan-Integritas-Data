import os
import hashlib
import binascii
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

# --- KONFIGURASI FOLDER ---
FOLDER_NAME = "user-keys"
if not os.path.exists(FOLDER_NAME):
    try:
        os.makedirs(FOLDER_NAME)
    except:
        pass

def get_key_path(username):
    # Path file tersimpan
    return (os.path.join(FOLDER_NAME, f"{username}_priv.pem"), 
            os.path.join(FOLDER_NAME, f"{username}_pub.pem"))

def generate_and_save_keys(username):
    print(f"\n[PROSES] Membuat kunci baru untuk: {username}")
    
    # Generate Key
    priv = ec.generate_private_key(ec.SECP256R1())
    
    # Format PEM Standar untuk disimpan di File
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Simpan ke file
    priv_path, pub_path = get_key_path(username)
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path, "wb") as f: f.write(pub_pem)
        
    print(f"[SUKSES] Kunci disimpan di folder '{FOLDER_NAME}'.")

def load_priv(username):
    path, _ = get_key_path(username)
    if not os.path.exists(path):
        print(f"[ERROR] File kunci {path} tidak ditemukan.")
        return None
    with open(path, "rb") as f: 
        return serialization.load_pem_private_key(f.read(), None)

def main():
    print("=== CLIENT APP: SIAP DEMO ===")
    
    while True:
        print("\n" + "="*40)
        print("1. Generate Key (Buat User Baru)")
        print("2. AMBIL PUBLIC KEY (1 Baris - Untuk Menu Store)")
        print("3. BUAT SIGNATURE TEKS (Untuk Menu Verify)")
        print("4. BUAT SIGNATURE PDF (Untuk Menu Verify PDF)")
        print("5. Enkripsi Pesan (Relay)")
        print("6. Dekripsi Pesan (Inbox)")
        print("0. Keluar")
        print("="*40)
        
        choice = input("Pilih Menu >> ")
        
        if choice == '1':
            u = input("Masukkan Username: ")
            generate_and_save_keys(u)
            
        elif choice == '2':
            u = input("Masukkan Username: ")
            _, pub_path = get_key_path(u)
            
            if os.path.exists(pub_path):
                with open(pub_path, "r") as f:
                    content = f.read()
                    
                    # --- MAGIC: UBAH JADI 1 BARIS ---
                    # Hapus header, footer, dan baris baru
                    clean = content.replace("-----BEGIN PUBLIC KEY-----", "")
                    clean = content.replace("-----END PUBLIC KEY-----", "")
                    clean = clean.replace("\n", "").strip()
                    
                    print("\n[COPY KODE 1 BARIS DI BAWAH INI]:")
                    print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
                    print(clean)
                    print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
            else:
                print("[ERROR] Key belum dibuat. Pilih menu 1 dulu.")

        elif choice == '3':
            u = input("Username Anda: ")
            priv = load_priv(u)
            if priv:
                msg = input("Pesan yang akan dikirim: ")
                # Sign
                sig = priv.sign(msg.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                sig_hex = sig.hex()
                
                print("\n[HASIL SIGNATURE - COPY HEX DI BAWAH]:")
                print("==================================================")
                print(sig_hex)
                print("==================================================")

        elif choice == '4':
            u = input("Username Anda: ")
            priv = load_priv(u)
            if priv:
                phash = input("Paste SHA256 Hash PDF dari Swagger: ")
                try:
                    # Sign Hash
                    sig = priv.sign(phash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                    sig_hex = sig.hex()
                    
                    print("\n[HASIL SIGNATURE PDF - COPY HEX DI BAWAH]:")
                    print("==================================================")
                    print(sig_hex)
                    print("==================================================")
                except Exception as e:
                    print(f"Error: {e}")

        elif choice == '5':
            msg = input("Pesan Rahasia: ")
            print(f"\n[HASIL ENKRIPSI]: {msg[::-1]}")
            
        elif choice == '6':
            cipher = input("Paste Ciphertext: ")
            print(f"\n[HASIL DEKRIPSI]: {cipher[::-1]}")
            
        elif choice == '0':
            break

if __name__ == "__main__":
    main()