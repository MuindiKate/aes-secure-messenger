import tkinter as tk
from tkinter import messagebox
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# === Shared AES Key ===
shared_key = "mysupersecretkey"  # 16 characters

def decrypt_message(encrypted_data):
    try:
        key_bytes = shared_key.encode('utf-8')
        iv, ct = encrypted_data.split(':')
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"[!] Decryption failed: {e}"

# === GUI ===
window = tk.Tk()
window.title("Receiver - AES Messenger")
window.geometry("600x400")

tk.Label(window, text="Paste Encrypted Message:").pack()
entry_encrypted = tk.Text(window, height=4, width=60)
entry_encrypted.pack()

entry_decrypted = tk.Text(window, height=3, width=60)
entry_decrypted.pack()
entry_decrypted.insert(tk.END, "Decrypted message will appear here...")

def handle_decrypt():
    encrypted_msg = entry_encrypted.get("1.0", tk.END).strip()
    if ':' not in encrypted_msg:
        messagebox.showerror("Invalid Format", "Encrypted message must contain ':'")
        return
    result = decrypt_message(encrypted_msg)
    entry_decrypted.delete("1.0", tk.END)
    entry_decrypted.insert(tk.END, result)

tk.Button(window, text="Decrypt", command=handle_decrypt).pack(pady=10)

window.mainloop()
