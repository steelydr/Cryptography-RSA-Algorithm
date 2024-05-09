
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode

class EncryptingMessage:
    def __init__(self, master):
        self.master = master
        self.master.title("Encrypting a message")

        self.bob_private_key, self.bob_public_key = self.generate_key_pair()

        self.label = tk.Label(master, text="Enter your message:")
        self.label.pack()

        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.pack()
        
        self.encrypt_button = tk.Button(master, text="Encrypt A Text", command=self.encrypt_message)
        self.encrypt_button.pack()

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_message(self):
        message = self.message_entry.get()
        encrypted_message = self.encrypt(message, self.bob_public_key)
        
        filename = "encrypted_message.txt"
        with open(filename, "w") as file:
            file.write(encrypted_message)

        private_key_bytes = self.bob_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open("bob_private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key_bytes)

        messagebox.showinfo("Encrypted Message", f"Encrypted Message Sent: {encrypted_message}")

    def encrypt(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return b64encode(ciphertext).decode('utf-8')


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptingMessage(root)
    root.mainloop()
    print("Encryption is done")
