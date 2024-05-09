import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from base64 import b64decode

def decrypt_message(encrypted_message, private_key):
    ciphertext = b64decode(encrypted_message.encode('utf-8'))
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

class DecryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Decryption App")
        self.geometry("400x300")

        # Load the private key from the file
        with open("bob_private_key.pem", "rb") as private_key_file:
            private_key_data = private_key_file.read()
            self.private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )

        # Load the encrypted message from the file
        with open("encrypted_message.txt", "r") as encrypted_file:
            self.encrypted_message = encrypted_file.read().strip()

        # Create a label to display the decrypted message
        self.decrypted_message_label = tk.Label(self, text="", wraplength=350)
        self.decrypted_message_label.pack(pady=20)

        # Create a button to decrypt the message
        self.decrypt_button = tk.Button(self, text="Decrypt Message", command=self.decrypt)
        self.decrypt_button.pack()

    def decrypt(self):
        decrypted_message = decrypt_message(self.encrypted_message, self.private_key)
        self.decrypted_message_label.config(text=decrypted_message)

if __name__ == "__main__":
    app = DecryptionApp()
    app.mainloop()