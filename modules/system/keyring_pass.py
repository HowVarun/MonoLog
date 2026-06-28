import base64
import keyring
from keyring.errors import KeyringError
from modules.crypto_core.pqc import MLDSA

class PrivateKeyManager:
    def __init__(self):
        self.service_name = "SecureVault_Device_Identity"
        self.account_name = "mldsa_private_key"

    def get_or_create_identity(self) -> MLDSA:
        try:
            encoded_pvt_key = keyring.get_password(self.service_name, self.account_name)
            if encoded_pvt_key:
                pvt_key_bytes = bytearray(base64.b64decode(encoded_pvt_key.encode('utf-8')))
                identity = MLDSA(secret_key=pvt_key_bytes)
                pvt_key_bytes[:] = 0 * len(pvt_key_bytes)
                return identity
            else:
                identity = MLDSA()
                identity.generate_key()
                encoded_new_key = base64.b64encode(identity.pvt_key).decode('utf-8')
                identity.pvt_key[:] = 0 * len(identity.pvt_key)      #Can Cause errors in future check
                keyring.set_password(self.service_name, self.account_name, encoded_new_key)
                return identity
        except KeyringError as e:
            raise SystemError(f"Platform keyring failure: {e}")

    def purge_identity(self) -> bool:
        try:
            keyring.delete_password(self.service_name, self.account_name)
            return True
        except KeyringError:
            return False

    