import os
import struct
import concurrent.futures
import portalocker
import shutil
import tempfile

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

        self.decrypt_aesgcm = None
        self.encrypt_aesgcm = None
    
    def run_vacuum(self):
        Defragmentation.vacuum()
    
    def change_vault_password(self, old_mp, old_wp, new_mp, new_wp):
        self.orchestrator.lock_vault()
        #==================================
        self.orchestrator.unlock_hash(old_mp, old_wp)
        local_dek = self.orchestrator.dek
        #==================================
        kek_salt = os.urandom(16)
        self.kdf = MfaKdf(existing_salt = kek_salt)
        kek = self.kdf.derive(new_mp, new_wp)
        #==================================
        self.aesgcm = AesGcm(kek)
        dek_iv, encrypted_dek = self.aesgcm.encrypt_cipherstream(local_dek)
        #==================================
        self.vaultio.atomic_header_swap(b'SCAF', '1.0.0', kek_salt, True)
        self.vaultio.atomic_lockbox_swap(dek_iv, encrypted_dek, True)
        #==================================
        backup_paths = (self.filepath + '.ahs', self.filepath + '.als')
        for backup_path in backup_paths:
            if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except OSError:
                        pass
        #==================================
        
    def prepare_vault_transfer(self, shared_secret: bytes):
        local_dek = self.orchestrator.dek
        if not local_dek:
            raise ValueError("Vault is locked")
        transit_aesgcm = AesGcm(shared_secret)
        dek_iv, dek_encrypted = transit_aesgcm.encrypt_cipherstream(local_dek)
        transit_path = os.path.join(tempfile.gettempdir(), f"{self.filepath}.tmp")
        shutil.copy2(self.filepath, transit_path)
        with open(transit_path, 'r+b') as tfile:
            tfile.seek(0)
            magic_num = struct.pack('>4s', b"TRAN")
            tfile.write(magic_num)
            tfile.seek(23)
            tfile.write( dek_iv + dek_encrypted)
            os.fsync(tfile.fileno())
        return transit_path
    
    def process_received_vault(self, received_tmp_path: str, final_dest_path: str, shared_secret: bytes, new_mp: str, new_wp: str):
        
        with open(received_tmp_path, 'r+b') as tfile:
            tfile.seek(0)
            magic_num = tfile.read(4)
            if magic_num != b"TRAN":
                raise ValueError("Invalid File State! Expected 'TRAN' magic number")
            tfile.seek(23)
            lockbox = tfile.read(60)
            dek_iv = lockbox[:12]
            dek_cipher = lockbox[12:]
            
            transit_aesgcm = AesGcm(shared_secret)
            dek = bytearray(transit_aesgcm.decrypt_cipherstream(dek_iv, dek_cipher))

            salt = os.urandom(16)
            kdf = MfaKdf(existing_salt = salt)
            kek = bytearray(kdf.derive(new_mp, new_wp))

            local_aesgcm = AesGcm(kek)
            ndek_iv, ndek_cipher = local_aesgcm.encrypt_cipherstream(dek)

            tfile.seek(23)
            tfile.write(ndek_iv + ndek_cipher)

            tfile.seek(0)
            tfile.write(b"SCAF")
            os.fsync(tfile.fileno())
        
        shutil.move(received_tmp_path, final_dest_path)
        dek[:] = b'\x00' * len(dek)
        kek[:] = b'\x00' * len(kek)
        return True
    
    #Changing DEK

    def _generate_file_list(self, active_virtual_paths: list):
        for vpath in active_virtual_paths:
            chunks = self.hashmap.get_meta(vpath)
            for chunk in chunks:
                yield (vpath, chunk['iv'], chunk['start'], chunk['end'])
    
    def _transfer_reencrypt_chunks(self, arguments: tuple):
        virtual_path, iv, start, end = arguments
        chunk_ct = self.vaultio.read_cargo(start, end)
        chunk_pt = bytearray(self.decrypt_aesgcm.decrypt_cipherstream(iv, chunk_ct))
        n_iv, n_chunk_ct = self.encrypt_aesgcm.encrypt_cipherstream(chunk_pt)
        chunk_pt[:] = b'\x00' * len(chunk_pt)
        return (virtual_path, n_iv, n_chunk_ct)
    
    def sync_map_to_disc(self, new_map_dict: dict, full_db_metadata: dict):
        tmp_hashmap = VaultMap()
        tmp_hashmap.map = new_map_dict
        nmap_pt = tmp_hashmap.restitch(full_db_metadata)
        #==================================
        nmap_iv, nmap_ciphertext = self.encrypt_aesgcm.encrypt_cipherstream(nmap_pt)
        #==================================
        nmap_P = self.tmpvaultio.get_eof()
        nmap_L = len(nmap_iv) + len(nmap_ciphertext)
        #==================================
        self.tmpvaultio.append_map(nmap_iv, nmap_ciphertext)
        #==================================
        identifier_pt = struct.pack('>QQ', nmap_P, nmap_L)
        iv_identifier, identifier_ct = self.encrypt_aesgcm.encrypt_cipherstream(identifier_pt)
        self.tmpvaultio.write_pointer(iv_identifier, identifier_ct)
        #==================================

    def rotate_titanium_dek(self, master_password: str, weak_password: str):
        """
        USE CAUTIOUSLY: Re-encrypts the entire vault (including .del_).
        """
        self.tmp_path = os.path.join(tempfile.gettempdir(), f"{os.path.basename(self.filepath)}.tmp")
        self.tmpvaultio = VaultIO(self.tmp_path)
        #==================================
        #initialize with vulnerable keys with bytearray for memory deletion later
        old_kek = bytearray(32)
        old_dek = bytearray(32)
        new_kek = bytearray(32)
        new_dek = bytearray(32)
        #==================================
        try:
            #authenticate & extract old key
            kdf = MfaKdf(existing_salt=self.orchestrator.salt)
            old_kek[:] = kdf.derive(master_password, weak_password)
            
            if old_kek != self.orchestrator.kek_hash:
                raise ValueError("Authentication failed. Cannot rotate DEK.")
            #==================================   
            kek_aes = AesGcm(old_kek)
            dek_iv, dek_cipher = self.vaultio.read_lockbox()
            old_dek[:] = kek_aes.decrypt_cipherstream(dek_iv, dek_cipher)
            new_dek[:] = os.urandom(32)
            new_salt = os.urandom(16)
            n_kdf = MfaKdf(existing_salt=new_salt)
            new_kek[:] = n_kdf.derive(master_password, weak_password)
            #==================================
            #encryption and decryption aesgcm class object
            self.encrypt_aesgcm = AesGcm(new_dek)
            self.decrypt_aesgcm = AesGcm(old_dek)
            #==================================
            new_kek_aes = AesGcm(new_kek)
            n_dek_iv, n_dek_cipher = new_kek_aes.encrypt_cipherstream(new_dek)
            #==================================
            full_db_metadata = self.vaultdb.get_complete_meta()
            vpath_list = list(self.hashmap.map.keys())
            new_map_dict = {vpath: [] for vpath in vpath_list}
            #==================================
            #portalocker is already held by VaultManager
            with self.orchestrator.io_lock:
                __, major, minor, patch, _ = self.vaultio.read_header()
                version_str = f"{major}.{minor}.{patch}"
                
                self.tmpvaultio.initialize_new_vault(
                    version=version_str, 
                    salt=new_salt, 
                    dek_iv=n_dek_iv, 
                    dek_cipher=n_dek_cipher, 
                    pointer_P=0, 
                    pointer_L=0
                )
                #==================================
                #mutli-threading encryption and writing
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    mapper = executor.map(self._transfer_reencrypt_chunks, self._generate_file_list(vpath_list))
                    for virtual_path, iv, ciphertext in mapper:
                        start = self.tmpvaultio.get_eof()
                        end = start + len(ciphertext)
                        
                        self.tmpvaultio.append_cargo(ciphertext)
                        new_map_dict[virtual_path].append({
                            "iv": iv,
                            "start": start,
                            "end": end
                        })
                #==================================
                self.sync_map_to_disc(new_map_dict, full_db_metadata)
                os.replace(self.tmp_path, self.filepath)
        
        #==================================
        #wiping shit from memory
        finally:
            if os.path.exists(self.tmp_path):
                try:
                    os.remove(self.tmp_path)
                except OSError:
                    pass
            
            #==================================
            old_kek[:] = b'\x00' * 32
            old_dek[:] = b'\x00' * 32
            new_kek[:] = b'\x00' * 32
            new_dek[:] = b'\x00' * 32
            #==================================
            self.decrypt_aesgcm = None
            self.encrypt_aesgcm = None
            #==================================
            self.orchestrator.lock_vault()
            #==================================