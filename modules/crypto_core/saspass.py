from cryptography.hazmat.primitives.kdf.hkdf import HKDF as hkdf
from cryptography.hazmat.primitives.hashes import SHA3_256


class SasPass:
    @staticmethod
    def derive_pass(*public_keys : bytes):
        hash_object = hkdf(
            algorithm = SHA3_256(),
            length = 32,
            salt = None,
            info = b"_securevault._tcp.local.",
            backend = None
            )
        public_key_list = [p for p in public_keys]
        public_key_list.sort()
        combined_pass = b"".join(public_key_list)

        hash = hash_object.derive(combined_pass)
        pin = int.from_bytes(hash, byteorder='big')
        pin = pin % 1000000
        return f"{pin:06d}"
    
    @staticmethod
    def verify_pass(PIN : str  ,*public_keys : bytes):
        expected_pin = SasPass.derive_pass(*public_keys)
        return expected_pin == PIN
            

