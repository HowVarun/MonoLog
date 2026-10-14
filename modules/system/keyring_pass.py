import base64
import keyring
from keyring.errors import KeyringError
from modules.crypto_core.pqc import MLDSA

class PrivateKeyManager:
    def __init__(self):
        self.service_name = "SecureVault_Device_Identity"
        self.account_base = "mldsa_pvt_part"

    def get_or_create_identity(self) -> MLDSA:
        try:
            parts = []
            # Dynamically read chunks until we hit a missing one
            for i in range(25):  
                part = keyring.get_password(self.service_name, f"{self.account_base}_{i}")
                if part:
                    parts.append(part)
                else:
                    break
            
            if parts:
                try:
                    encoded_pvt_key = "".join(parts)
                    pvt_key_bytes = bytearray(base64.b64decode(encoded_pvt_key.encode('utf-8')))
                    identity = MLDSA(secret_key=pvt_key_bytes)
                    pvt_key_bytes[:] = b'\x00' * len(pvt_key_bytes)
                    return identity
                except Exception:
                    # If corrupted by a previous crash, purge and regenerate below
                    self.purge_identity()

            # Generate new key
            identity = MLDSA()
            pvt_key_bytes = bytearray(identity.generate_key(key_type="pvt"))
            encoded_new_key = base64.b64encode(pvt_key_bytes).decode('utf-8')
            
            # Slice into ultra-safe 500-character micro-chunks
            chunk_size = 500
            chunks = [encoded_new_key[i:i+chunk_size] for i in range(0, len(encoded_new_key), chunk_size)]
            
            for i, chunk in enumerate(chunks):
                keyring.set_password(self.service_name, f"{self.account_base}_{i}", chunk)
                
            pvt_key_bytes[:] = b'\x00' * len(pvt_key_bytes)
            return identity
            
        except KeyringError as e:
            raise SystemError(f"Platform keyring failure: {e}")

    def purge_identity(self) -> bool:
        try:
            for i in range(25):
                try:
                    keyring.delete_password(self.service_name, f"{self.account_base}_{i}")
                except KeyringError:
                    pass
            return True
        except Exception:
            return False