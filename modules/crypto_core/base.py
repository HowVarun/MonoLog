from abc import ABC, abstractmethod

class SymmetricCipherEngine(ABC):
    def __init__(self, hashed_key):
        self.hashed_key = hashed_key
        self._chunk_size = 2*1024
        
    @property
    def hashed_key(self):
        return self._hashed_key
        
    @hashed_key.setter
    def hashed_key(self, value):
        if len(value) != 32:
            raise ValueError("The hashed key not 32 bytes")
        self._hashed_key = value        
    
    @abstractmethod
    def encrypt_cipherstream(self):
        pass

    @abstractmethod
    def decrypt_cipherstream(self):
        pass
