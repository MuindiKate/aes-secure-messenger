import tkinter as tk
from tkinter import messagebox
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import africastalking

# === Africa's Talking Setup ===
username = "sandbox"
api_key = "atsk_649b7b7efeba8ee23ca43d0a96bdf05e2da088b21e52feb8d8fdc1887d66d00bd1cb89ad"
receiver_number = "+254700000000"  # Use sandbox number

africastalking.initialize(username, api_key)
sms = africastalking.SMS

# === AES Helper Functions ===
def generate_key(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encrypt_message(message, key):
    key_bytes = key.encode('utf-8')[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt_message(encrypted_data, key):
    try:
        key_bytes = key.encode('utf-8')[:16]
        iv, ct = encrypted_data.split(':')
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"[!] Decryption failed: {e}"

def send_otp_via_sms(otp):
    message = f"Your OTP key for decryption is: {otp}"
    try:
        sms.send(message, [receiver_number])
        return "[+] OTP sent via SMS."
    except Exception as e:
        return f"[!] Error sending OTP: {e}"

# === GUI Setup ===
window = tk.Tk()
window.title("Secure AES Messenger")
window.geometry("600x500")

# === Widgets ===

# Message Input
tk.Label(window, text="Enter Message:").pack()
entry_message = tk.Text(window, height=4, width=60)
entry_message.pack()

# Encrypt Button
tk.Button(window, text="Encrypt & Send OTP", command=lambda: handle_encrypt()).pack(pady=(5, 10))

# Encrypted Message Display
tk.Label(window, text="Encrypted Message:").pack()
entry_encrypted = tk.Text(window, height=3, width=60)
entry_encrypted.pack()

# OTP Input
tk.Label(window, text="Enter OTP:").pack()
entry_otp = tk.Entry(window, width=30)
entry_otp.pack()

# Decrypt Button
tk.Button(window, text="Decrypt", command=lambda: handle_decrypt()).pack(pady=(5, 10))

# Decrypted Message Display
tk.Label(window, text="Decrypted Message:").pack()
entry_decrypted = tk.Text(window, height=3, width=60)
entry_decrypted.pack()

# === Handlers ===
def handle_encrypt():
    msg = entry_message.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showwarning("Empty", "Please enter a message.")
        return
    key = generate_key()
    encrypted = encrypt_message(msg, key)
    entry_encrypted.delete("1.0", tk.END)
    entry_encrypted.insert(tk.END, encrypted)
    status = send_otp_via_sms(key)
    messagebox.showinfo("Encryption Done", f"Encrypted and sent OTP.\n\n{status}")

def handle_decrypt():
    encrypted_msg = entry_encrypted.get("1.0", tk.END).strip()
    otp = entry_otp.get().strip()
    if not encrypted_msg or not otp:
        messagebox.showwarning("Missing Data", "Please provide both Encrypted Message and OTP.")
        return
    decrypted = decrypt_message(encrypted_msg, otp)
    entry_decrypted.delete("1.0", tk.END)
    entry_decrypted.insert(tk.END, decrypted)

# === Run GUI ===
window.mainloop()
