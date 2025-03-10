# encrypt.py
import base64
from cryptography.fernet import Fernet
import hashlib

class FileSecurity:
    """
    Handles file encryption and checksum generation.
    """
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_data(self, data: bytes) -> (bytes, str):
        """Encrypts data and returns the encrypted data and the key (encoded)."""
        encrypted_data = self.cipher.encrypt(data)
        encoded_key = base64.urlsafe_b64encode(self.key).decode()
        return encrypted_data, encoded_key

    def decrypt_data(self, encrypted_data: bytes, encoded_key: str) -> bytes:
        """Decrypts data using the provided key."""
        cipher = Fernet(base64.urlsafe_b64decode(encoded_key))
        return cipher.decrypt(encrypted_data)

    def generate_checksum(self, data: bytes) -> str:
        """Generates a SHA-256 checksum for the data."""
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()