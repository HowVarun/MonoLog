import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class MfaKdf:
    def __init__(self, iterations = 2, lanes = 4, memory = 64*1024, existing_salt = None):
        self.iterations = iterations
        self.lanes = lanes
        self.memory = memory
        self._used = False
        if existing_salt is not None:
            self.salt = existing_salt
        else:
            self.salt = os.urandom(16)
        
    @property
    def salt (self):
        return self._salt
    
    @salt.setter
    def salt(self, value):
        if isinstance(value, bytes):
            if len(value) == 16:
                self._salt = value
            else:
                raise ValueError("Salt must be 16 bytes")
        else:
            raise TypeError("Invalid salt type")
    
    def derive(self,  master_password, weak_password):
        if not self._used:    
            master_password = master_password.encode('utf-8') 
            weak_password = weak_password.encode('utf-8') 
            kdf1 = Argon2id(self._salt, 16, self.iterations, self.lanes, self.memory)
            hidden_salt = kdf1.derive(weak_password)
            kdf2 = Argon2id(hidden_salt, 32, self.iterations, self.lanes, self.memory)
            self.hash = kdf2.derive(master_password)
            self._used = True
            master_password = b""
            weak_password = b""
            hidden_salt = b""
            return(self.hash)
        else: 
            raise Exception("Instance already used, cannot use more than once")
    def verify(self, master_password, weak_password, hash):
        if self._used is False:
            if self.derive(master_password, weak_password) == hash:
                return True
            else:
                return False

