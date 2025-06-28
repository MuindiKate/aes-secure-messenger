import tkinter as tk
from tkinter import messagebox
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import africastalking

# === Africa's Talking Setup ===
username = "CyptoAce" #My App username
api_key = "atsk_14c65191971413f08cbc603c4b7571386581cf0f2a42b0df88df914406211b9638f23b4a"
receiver_number = "+254788364422"  # Airtel number

africastalking.initialize(username, api_key)
sms = africastalking.SMS

# === AES Setup ===
shared_key = "mysupersecretkey"  # 16 characters

def encrypt_message(message):
    key_bytes = shared_key.encode('utf-8')
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def send_sms(encrypted_message):
    message = f"Encrypted Message:\n{encrypted_message}"
    try:
        sms.send(message, [receiver_number])
        return "[+] Encrypted message sent via SMS."
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
    encrypted = encrypt_message(msg)
    entry_encrypted.delete("1.0", tk.END)
    entry_encrypted.insert(tk.END, encrypted)
    sms_status = send_sms(encrypted)
    messagebox.showinfo("Success", f"Message encrypted and sent.\n\n{sms_status}")

tk.Button(window, text="Encrypt & Send", command=handle_encrypt).pack(pady=10)
tk.Label(window, text="Encrypted message will also be sent via SMS.").pack()

window.mainloop()
