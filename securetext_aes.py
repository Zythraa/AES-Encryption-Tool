import sys
import base64
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QPushButton, QRadioButton, QButtonGroup, QMessageBox, QLineEdit, QStatusBar
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import pyperclip

class AESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES Encryption Tool")
        self.setGeometry(200, 100, 750, 680)
        self.setWindowIcon(QIcon())
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout()

        font_bold = QFont()
        font_bold.setPointSize(10)
        font_bold.setBold(True)

        # Input Section
        label_input = QLabel("Input Text (to Encrypt):")
        label_input.setFont(font_bold)
        main_layout.addWidget(label_input)

        self.input_text = QTextEdit()
        main_layout.addWidget(self.input_text)

        # Password Section
        label_pass = QLabel("Password (for key derivation):")
        label_pass.setFont(font_bold)
        main_layout.addWidget(label_pass)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter a password (PBKDF2 will derive the AES key)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        main_layout.addWidget(self.password_input)

        # Key Size Selection
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Key Size:"))
        self.key_group = QButtonGroup()
        for bits in [128, 192, 256]:
            btn = QRadioButton(f"{bits} bits")
            if bits == 128:
                btn.setChecked(True)
            self.key_group.addButton(btn, bits)
            key_layout.addWidget(btn)
        main_layout.addLayout(key_layout)

        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.copy_encrypt_button = QPushButton("Copy Encrypted")
        self.copy_decrypt_button = QPushButton("Copy Decrypted")
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.copy_encrypt_button)
        button_layout.addWidget(self.copy_decrypt_button)
        main_layout.addLayout(button_layout)

        # Encrypted Output
        main_layout.addWidget(QLabel("Encrypted Output (Base64):"))
        self.encrypted_output = QTextEdit()
        main_layout.addWidget(self.encrypted_output)

        # Decrypted Output
        main_layout.addWidget(QLabel("Decrypted Output (Plaintext):"))
        self.decrypted_output = QTextEdit()
        main_layout.addWidget(self.decrypted_output)

        # Status bar
        self.status = QStatusBar()
        main_layout.addWidget(self.status)

        # Events
        self.encrypt_button.clicked.connect(self.encrypt_message)
        self.decrypt_button.clicked.connect(self.decrypt_message)
        self.copy_encrypt_button.clicked.connect(self.copy_encrypted)
        self.copy_decrypt_button.clicked.connect(self.copy_decrypted)

        self.setLayout(main_layout)

    def derive_key(self, password, bits):
        salt = b'student_salt'  # For demo purposes only
        return PBKDF2(password, salt, dkLen=bits // 8, count=100_000)

    def encrypt_message(self):
        message = self.input_text.toPlainText().strip()
        password = self.password_input.text().strip()
        key_size = self.key_group.checkedId()

        if not message or not password:
            self.status.showMessage("Enter both input text and password.", 5000)
            return

        try:
            key = self.derive_key(password, key_size)
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
            result = base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
            self.encrypted_output.setPlainText(result)
            self.status.showMessage("Message encrypted successfully.", 5000)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))

    def decrypt_message(self):
        ciphertext = self.encrypted_output.toPlainText().strip()
        password = self.password_input.text().strip()
        key_size = self.key_group.checkedId()

        if not ciphertext or not password:
            self.status.showMessage("Provide both ciphertext and password.", 5000)
            return

        try:
            key = self.derive_key(password, key_size)
            raw = base64.b64decode(ciphertext)
            iv = raw[:16]
            ct = raw[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            self.decrypted_output.setPlainText(pt.decode('utf-8'))
            self.status.showMessage("Message decrypted successfully.", 5000)
        except Exception:
            QMessageBox.warning(self, "Incorrect Password", "Decryption failed. Please check your password or key size.")

    def copy_encrypted(self):
        output = self.encrypted_output.toPlainText().strip()
        if output:
            pyperclip.copy(output)
            self.status.showMessage("Encrypted output copied to clipboard.", 3000)
        else:
            self.status.showMessage("Nothing to copy.", 3000)

    def copy_decrypted(self):
        output = self.decrypted_output.toPlainText().strip()
        if output:
            pyperclip.copy(output)
            self.status.showMessage("Decrypted output copied to clipboard.", 3000)
        else:
            self.status.showMessage("Nothing to copy.", 3000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AESApp()
    window.show()
    sys.exit(app.exec())
