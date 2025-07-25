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
3. The private key is sent via OTP SMS using **Africa’s Talking**
4. Encrypted message is displayed and can be copied/shared via email/ whatsapp

 Receiver
1. Receives the private key via SMS.
2. Copy pastes and Inputs the encrypted message sent earlier and the private key sent via SMS
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
* OTP SMS will appear on a real phone as it is a Live app.
* Manual transfer of encrypted messages simulates remote communication.



