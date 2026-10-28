import base64
import keyring
import os

from keyring.errors import KeyringError
from modules.crypto_core.pqc import MLDSA

class PrivateKeyManager:
    def __init__(self):
        node_id = os.getenv("SV_NODE", "1")
        suffix = f"_{node_id}" if node_id != "1" else ""
        self.service_name = f"SecureVault_Device_Identity{suffix}"
        
        # Track both Private and Public parts for FIPS 204 compliance
        self.account_base_pvt = "mldsa_pvt_part"
        self.account_base_pub = "mldsa_pub_part"

    def get_or_create_identity(self) -> MLDSA:
        try:
            pvt_parts = []
            pub_parts = []
            
            # Dynamically read PVT chunks
            for i in range(25):  
                part = keyring.get_password(self.service_name, f"{self.account_base_pvt}_{i}")
                if part: pvt_parts.append(part)
                else: break
                    
            # Dynamically read PUB chunks
            for i in range(25):  
                part = keyring.get_password(self.service_name, f"{self.account_base_pub}_{i}")
                if part: pub_parts.append(part)
                else: break
            
            # If BOTH keys were found in the Keyring
            if pvt_parts and pub_parts:
                try:
                    encoded_pvt_key = "".join(pvt_parts)
                    encoded_pub_key = "".join(pub_parts)
                    
                    pvt_key_bytes = bytearray(base64.b64decode(encoded_pvt_key.encode('utf-8')))
                    pub_key_bytes = bytearray(base64.b64decode(encoded_pub_key.encode('utf-8')))
                    
                    # Pass BOTH into the updated MLDSA class
                    identity = MLDSA(secret_key=bytes(pvt_key_bytes), public_key=bytes(pub_key_bytes))
                    
                    pvt_key_bytes[:] = b'\x00' * len(pvt_key_bytes)
                    return identity
                except Exception:
                    # If corrupted by a previous crash, purge and regenerate below
                    self.purge_identity()

            # Generate new key pair
            identity = MLDSA()
            
            # Extract both from the new identity
            pvt_key_bytes = bytearray(identity.generate_key(key_type="pvt"))
            pub_key_bytes = bytearray(identity.generate_key(key_type="pub"))
            
            encoded_new_pvt = base64.b64encode(pvt_key_bytes).decode('utf-8')
            encoded_new_pub = base64.b64encode(pub_key_bytes).decode('utf-8')
            
            # Slice into ultra-safe 500-character micro-chunks
            chunk_size = 500
            pvt_chunks = [encoded_new_pvt[i:i+chunk_size] for i in range(0, len(encoded_new_pvt), chunk_size)]
            pub_chunks = [encoded_new_pub[i:i+chunk_size] for i in range(0, len(encoded_new_pub), chunk_size)]
            
            # Store PVT chunks
            for i, chunk in enumerate(pvt_chunks):
                keyring.set_password(self.service_name, f"{self.account_base_pvt}_{i}", chunk)
                
            # Store PUB chunks
            for i, chunk in enumerate(pub_chunks):
                keyring.set_password(self.service_name, f"{self.account_base_pub}_{i}", chunk)
                
            pvt_key_bytes[:] = b'\x00' * len(pvt_key_bytes)
            return identity
            
        except KeyringError as e:
            raise SystemError(f"Platform keyring failure: {e}")

    def purge_identity(self) -> bool:
        try:
            for i in range(25):
                # Attempt to delete both PVT and PUB chunks
                try:
                    keyring.delete_password(self.service_name, f"{self.account_base_pvt}_{i}")
                except KeyringError:
                    pass
                    
                try:
                    keyring.delete_password(self.service_name, f"{self.account_base_pub}_{i}")
                except KeyringError:
                    pass
            return True
        except Exception:
            return False