import tkinter as tk
from tkinter import messagebox
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import africastalking

# === Africa's Talking Setup ===
username = "sandbox"
api_key = "atsk_649b7b7efeba8ee23ca43d0a96bdf05e2da088b21e52feb8d8fdc1887d66d00bd1cb89ad"
receiver_number = "+254790049202"  # Sandbox test number

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

def send_otp_via_sms(otp):
    message = f"Your OTP key for decryption is: {otp}"
    try:
        sms.send(message, [receiver_number])
        return "[+] OTP sent via SMS."
    except Exception as e:
        return f"[!] Error sending OTP: {e}"

# === GUI Setup ===
window = tk.Tk()
window.title("Sender - AES Secure Messenger")
window.geometry("600x400")

tk.Label(window, text="Enter Message to Encrypt:").pack()
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
    status = send_otp_via_sms(key)
    messagebox.showinfo("Done", f"Encrypted and OTP sent.\n\n{status}")

tk.Button(window, text="Encrypt & Send OTP", command=handle_encrypt).pack(pady=10)

tk.Label(window, text="Copy the encrypted message and send it to the receiver.").pack(pady=(5, 0))

window.mainloop()
