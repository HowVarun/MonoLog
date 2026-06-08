from cryptography.hazmat.primitives.kdf.hkdf import HKDF as hkdf
from cryptography.hazmat.primitives.hashes import SHA3_256



class SasPass:
    def __init__ (self):
        pass
    
    def derive_pass(self, *public_keys : bytes):
        self.hash_object = hkdf(
            algorithm = SHA3_256(),
            length = 32,
            salt = None,
            info = b"_securevault._tcp.local.",
            backend = None
            )
        public_key_list = [p for p in public_keys]
        public_key_list.sort()
        combined_pass = b"".join(public_key_list)

        hash = self.hash_object.derive(combined_pass)
        pin = int.from_bytes(hash, byteorder='big')
        pin = pin % 1000000
        return f"{pin:06d}"

    def verify_pass(self, PIN : str  ,*public_keys : bytes):
        expected_pin = self.derive_pass(*public_keys)
        if expected_pin == PIN:
            return True
        else:
            return False

