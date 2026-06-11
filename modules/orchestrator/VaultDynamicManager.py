import os
import struct
import concurrent.futures
import portalocker

from modules.system import VaultIO
from modules.vaultmap import VaultMap
from modules.crypto_core import AesGcm, MfaKdf
from modules.daemons import Defragmentation

class VaultDynamicManager:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.vaultdb = orchestrator.vaultdb
        self.hashmap = orchestrator.hashmap
        self.vaultio = orchestrator.vaultio
        self.filepath = orchestrator.filepath
    
    def run_vacuum(self):
        Defragmentation.vacuum()
    
    def change_vault_password(self, old_mp, old_wp, new_mp, new_wp):
        self.orchestrator.lock_vault()
        self.orchestrator.unlock_hash(old_mp, old_wp)
        local_dek = self.orchestrator.dek
        kek_salt = os.urandom(16)
        self.kdf = MfaKdf(existing_salt = kek_salt)
        kek = self.kdf.derive(new_mp, new_wp)
        self.aesgcm = AesGcm(kek)
        dek_iv, encrypted_dek = self.aesgcm.encrypt_cipherstream(local_dek)
        self.vaultio.atomic_header_swap(b'SCAF', '1.0.0', kek_salt, True)
        self.vaultio.atomic_lockbox_swap(dek_iv, encrypted_dek, True)
        backup_paths = (self.filepath + '.ahs', self.filepath + '.als')
        for backup_path in backup_paths:
            if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except OSError:
                        pass
        