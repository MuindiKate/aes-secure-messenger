import tkinter as tk
from tkinter import messagebox
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import africastalking

# === Africa's Talking Setup ===
username = "CyptoAce" 
api_key = "atsk_14c65191971413f08cbc603c4b7571386581cf0f2a42b0df88df914406211b9638f23b4a"
receiver_number = "+254788364422"  # Airtel number

africastalking.initialize(username, api_key)
sms = africastalking.SMS

# === Key + Encryption ===
def generate_key(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encrypt_message(message, key):
    key_bytes = key.encode('utf-8')[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def send_sms(key):
    message = f"Your OTP key for decryption is: {key}"
    try:
        sms.send(message, [receiver_number])
        return "[+] OTP key sent via SMS."
    except Exception as e:
        return f"[!] SMS failed: {e}"

# === GUI ===
window = tk.Tk()
window.title("Sender - AES Messenger")
window.geometry("600x400")

tk.Label(window, text="Enter Message:").pack()
entry_message = tk.Text(window, height=4, width=60)
entry_message.pack()

entry_encrypted = tk.Text(window, height=3, width=60)
entry_encrypted.pack()
entry_encrypted.insert(tk.END, "Encrypted message will appear here...")

def handle_encrypt():
    msg = entry_message.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showwarning("Empty", "Please enter a message.")
        return
    key = generate_key()
    encrypted = encrypt_message(msg, key)
    entry_encrypted.delete("1.0", tk.END)
    entry_encrypted.insert(tk.END, encrypted)
    sms_status = send_sms(key)
    messagebox.showinfo("Success", f"Message encrypted.\n\n{sms_status}\n\nNow send the encrypted message to the receiver manually.")

tk.Button(window, text="Encrypt & Send OTP", command=handle_encrypt).pack(pady=10)
tk.Label(window, text="Send the encrypted message separately (WhatsApp, email, etc).").pack()

window.mainloop()
