
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

st.set_page_config(page_title="AES File Encryptor", page_icon="🔐")

def gen_key():
    return AESGCM.generate_key(bit_length=256)

def encrypt_file(key, data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_file(key, data):
    aesgcm = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ct, None)

st.title("🔐 AES-GCM File Encryptor / Decryptor")
st.write("Securely encrypt or decrypt any file using AES-GCM (256-bit).")

mode = st.radio("Select Mode", ["Encrypt", "Decrypt"])
uploaded_file = st.file_uploader("Upload a file", type=None)

keyfile = st.file_uploader("Upload key file (for decrypt only)", type=["bin"]) if mode == "Decrypt" else None

if st.button("Run"):
    if uploaded_file is not None:
        file_data = uploaded_file.read()
        
        if mode == "Encrypt":
            key = gen_key()
            encrypted = encrypt_file(key, file_data)
            st.success("✅ File Encrypted Successfully!")

            st.download_button("⬇️ Download Encrypted File", encrypted, file_name="encrypted.bin")
            st.download_button("⬇️ Download Key File", key, file_name="img_key.bin")

        elif mode == "Decrypt":
            if keyfile is None:
                st.error("⚠️ Please upload the key file to decrypt.")
            else:
                try:
                    key = keyfile.read()
                    decrypted = decrypt_file(key, file_data)
                    st.success("✅ File Decrypted Successfully!")
                    st.download_button("⬇️ Download Decrypted File", decrypted, file_name="decrypted_output.bin")
                except Exception as e:
                    st.error(f"❌ Decryption failed: {e}")
    else:
        st.warning("⚠️ Please upload a file first.")
