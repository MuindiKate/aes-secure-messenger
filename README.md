 AES Secure Messenger

A Python-based secure messaging application using **AES symmetric encryption** and **OTP key delivery via SMS** (Africa's Talking API). Built with a simple GUI in `tkinter`, this project simulates encrypted communication between two remote users.

📌 Features

- ✅ AES encryption and decryption using `pycryptodome`
- ✅ OTP key generation and SMS delivery via Africa’s Talking
- ✅ Two separate apps: **Sender** and **Receiver**
- ✅ User-friendly `tkinter` GUI
- ✅ Secure OTP-based decryption
- ✅ Simulates remote communication via message copy-paste



 How It Works
 Sender
1. Enters a message
2. App encrypts it with a randomly generated AES key
3. OTP key is sent via SMS using **Africa’s Talking**
4. Encrypted message is displayed and can be copied/shared

 Receiver
1. Receives the encrypted message via any channel (email, WhatsApp, etc.)
2. Inputs the encrypted message and OTP
3. App decrypts and displays the original message

 Technologies Used

- `Python 3.10+`
- `pycryptodome` – for AES encryption
- `africastalking` – for SMS OTP API
- `tkinter` – for GUI interface


Setup Instructions

1. **Clone the repo**

```bash
git clone https://github.com/MuindiKate/aes-secure-messenger.git
cd aes-secure-messenger
```

2. **Install dependencies**

```bash
pip install pycryptodome africastalking
```

3. **Run the apps**

```bash
# Sender side
python sender_gui.py

# Receiver side
python receiver_gui.py
```

---

##  Notes

* This project uses **Africa’s Talking sandbox** to simulate OTP delivery.
* OTP SMS will appear in the **Africa’s Talking SMS logs**, not on a real phone unless you go live.
* Manual transfer of encrypted messages simulates remote communication.



