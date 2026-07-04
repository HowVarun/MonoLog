from oqs.oqs import Signature, KeyEncapsulation

class MLDSA:
    def __init__(self, secret_key: bytes = None):
        self.algorithm = 'ML-DSA-87'
        self.has_key = False
        
        if not secret_key:
            self.signature = Signature(self.algorithm)
        else:
            self.signature = Signature(self.algorithm, secret_key)
            self.has_key = True
    
    def generate_key(self, type : str):
        if not self.has_key:
            pub_key = bytearray(self.signature.generate_keypair())
            _pvt_key = bytearray(self.signature.export_secret_key())
            self.has_key = True
        else:
            _pvt_key = bytearray(self.signature.export_secret_key())
            pub_key = bytearray(_pvt_key[-2592:])

        if type == "pub":
            _pvt_key[:] = b'\x00' * len(_pvt_key)
            return pub_key
        elif type == "pvt":
            pub_key[:] = b'\x00' * len(pub_key)
            return _pvt_key
        else:
            raise ValueError("Did not receive valid type")
    
    def sign(self, message: bytes):
        if not self.has_key:
            raise ValueError("No secret key loaded. Generate or pass a key first.")
        return self.signature.sign(message)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes):
        with Signature('ML-DSA-87') as local_sign:
            try:
                return(local_sign.verify(message, signature, public_key))
            except Exception:
                return False
                
    def close(self):
        
        if hasattr(self, 'signature') and hasattr(self.signature, 'free'):
            self.signature.free()

    def __del__(self):
        self.close()

class MLKEM:
    def __init__(self, secret_key: bytes = None):
        self.algorithm = 'ML-KEM-1024'
        self.has_key = False
        self.pub_key = None
        self.pvt_key = None
        
        if secret_key:
            self.keyencapsulation = KeyEncapsulation(self.algorithm, secret_key)
            self.has_key = True
        else:
            self.keyencapsulation = KeyEncapsulation(self.algorithm)
        
    def generate_key(self, type : str):
        """
        MANDATORY FIRST STEP:
        Populates self.pvt_key and self.pub_key whether starting fresh or from an existing key.
        """
        if not self.has_key:
            self.pub_key = self.keyencapsulation.generate_keypair()
            self.pvt_key = self.keyencapsulation.export_secret_key()
            self.has_key = True
        else:
            self.pvt_key = self.keyencapsulation.export_secret_key()
            self.pub_key = self.pvt_key[-1568:]
        
        if type == "pub":
            return self.pub_key
        elif type == "pvt":
            return self.pvt_key
        else:
            raise ValueError("Did not receive valid type")

    def encapsulate(self, peer_public_key: bytes):
        try:
            kem_cipher, shared_secret = self.keyencapsulation.encap_secret(peer_public_key)
            return kem_cipher, shared_secret
        except Exception:
            return False
    
    def decapsulate(self, kem_cipher: bytes):
        if not self.pvt_key:
            raise ValueError("State uninitialized. You must call generate_key() before decapsulating.")
            
        try:
            with KeyEncapsulation(self.algorithm, self.pvt_key) as decap:
                shared_secret = decap.decap_secret(kem_cipher)
                return shared_secret
        except Exception:
            return False

    def close(self):
        if hasattr(self, 'keyencapsulation') and hasattr(self.keyencapsulation, 'free'):
            self.keyencapsulation.free()
        self.pub_key = None
        self.pvt_key = None
    
    def __del__(self):
        self.close()