import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .base import SymmetricCipherEngine

class AesGcm(SymmetricCipherEngine):
    def __init__(self, hashed_key: bytes):
        super().__init__(hashed_key)
        self._cipher = AESGCM(self._hashed_key)

   

    def encrypt_cipherstream(self, aes_plaintext , iv = None):
        if iv:
            aes_cipher = self._cipher.encrypt(iv, aes_plaintext, None)
            return iv, aes_cipher
        else:
            iv = os.urandom(12)
            aes_cipher = self._cipher.encrypt(iv, aes_plaintext, None)
            return iv, aes_cipher
        
    
    def decrypt_cipherstream(self, iv, aes_cipher):
        
        aes_plaintext = self._cipher.decrypt(iv, aes_cipher, None)
        return aes_plaintext
    
    
        