import rsa
import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import Ui_MainWindow
import requests

# Create directory if it doesn't exist
if not os.path.exists('cipher/rsa/keys'):
    os.makedirs('cipher/rsa/keys')

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(1024)
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        return rsa.encrypt(message.encode('ascii'), key)

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False

    def sign(self, message, key):
        return rsa.sign(message.encode('ascii'), key, 'SHA-1')

    def verify(self, message, signature, key):
        try:
            return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
        except:
            return False


class MyApp(QMainWindow): 
    def __init__(self): 
        super().__init__() 
        self.ui = Ui_MainWindow() 
        self.ui.setupUi(self) 
        self.ui.btn_gen_keys.clicked.connect(self.call_api_gen_keys) 
        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt) 
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt) 
        self.ui.btn_sign.clicked.connect(self.call_api_sign) 
        self.ui.btn_verify.clicked.connect(self.call_api_verify) 
        self.rsa_cipher = RSACipher()

    def call_api_gen_keys(self): 
        self.rsa_cipher.generate_keys()  # Generate RSA keys
        msg = QMessageBox() 
        msg.setIcon(QMessageBox.Information) 
        msg.setText("Keys generated successfully!") 
        msg.exec_()

    def call_api_encrypt(self): 
        message = self.ui.txt_plain_text.toPlainText() 
        private_key, public_key = self.rsa_cipher.load_keys()
        encrypted_message = self.rsa_cipher.encrypt(message, public_key)
        self.ui.txt_cipher_text.setText(encrypted_message.hex())  # Show hex representation
        msg = QMessageBox() 
        msg.setIcon(QMessageBox.Information) 
        msg.setText("Encrypted Successfully") 
        msg.exec_()

    def call_api_decrypt(self): 
        encrypted_message = bytes.fromhex(self.ui.txt_cipher_text.toPlainText()) 
        private_key, public_key = self.rsa_cipher.load_keys()
        decrypted_message = self.rsa_cipher.decrypt(encrypted_message, private_key)
        if decrypted_message:
            self.ui.txt_plain_text.setText(decrypted_message)
            msg = QMessageBox() 
            msg.setIcon(QMessageBox.Information) 
            msg.setText("Decrypted Successfully") 
            msg.exec_() 
        else: 
            msg = QMessageBox() 
            msg.setIcon(QMessageBox.Warning) 
            msg.setText("Decryption Failed") 
            msg.exec_()

    def call_api_sign(self): 
        message = self.ui.txt_info.toPlainText() 
        private_key, public_key = self.rsa_cipher.load_keys()
        signature = self.rsa_cipher.sign(message, private_key)
        self.ui.txt_sign.setText(signature.hex())  # Show hex signature
        msg = QMessageBox() 
        msg.setIcon(QMessageBox.Information) 
        msg.setText("Signed Successfully") 
        msg.exec_()

    def call_api_verify(self): 
        message = self.ui.txt_info.toPlainText() 
        signature = bytes.fromhex(self.ui.txt_sign.toPlainText())
        private_key, public_key = self.rsa_cipher.load_keys()
        is_verified = self.rsa_cipher.verify(message, signature, public_key)
        msg = QMessageBox() 
        msg.setIcon(QMessageBox.Information) 
        if is_verified:
            msg.setText("Verified Successfully") 
        else:
            msg.setText("Verification Failed") 
        msg.exec_()


if __name__ == "__main__": 
    app = QApplication(sys.argv) 
    window = MyApp() 
    window.show() 
    sys.exit(app.exec_())
