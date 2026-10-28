import os
import struct
import concurrent.futures
import portalocker
import shutil
import tempfile
import random

from modules.system import VaultIO
from modules.vaultmap import VaultMap
from modules.crypto_core import AesGcm, MfaKdf
from modules.daemons import Defragmentation

class VaultDynamicManager:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.vaultio = orchestrator.vaultio
        self.filepath = orchestrator.filepath

        self.decrypt_aesgcm = None
        self.encrypt_aesgcm = None
    
    def run_vacuum(self):
        defrag = Defragmentation(self.orchestrator)
        defrag.vacuum()
        #==================================
    
    def change_vault_password(self, old_mp, old_wp, new_mp, new_wp):
            kdf = MfaKdf(existing_salt=self.orchestrator.salt)
            old_kek = kdf.derive(old_mp, old_wp)
            
            if bytearray(old_kek) != self.orchestrator.kek_hash:
                raise ValueError("Authentication failed. Invalid current password.")
                
            #generate new salt and derive the new kek
            new_salt = os.urandom(16)
            new_kdf = MfaKdf(existing_salt=new_salt)
            new_kek = new_kdf.derive(new_mp, new_wp)
            
            #encrypt the existing ram dek using the new kek
            self.aesgcm = AesGcm(new_kek)
            dek_iv, encrypted_dek = self.aesgcm.encrypt_cipherstream(self.orchestrator.dek)
            
            #execute atomic swaps on the physical file
            with self.orchestrator.io_lock:
                self.vaultio.atomic_header_swap(b'SCAF', '1.0.0', new_salt, True)
                self.vaultio.atomic_lockbox_swap(dek_iv, encrypted_dek, True)
                
                #clean up
                backup_paths = (self.filepath + '.ahs', self.filepath + '.als')
                for backup_path in backup_paths:
                    if os.path.exists(backup_path):
                        try:
                            os.remove(backup_path)
                        except OSError:
                            pass
                            
                self.orchestrator.salt = new_salt
                self.orchestrator.kek_hash[:] = bytearray(new_kek)
        
    def prepare_vault_transfer(self, shared_secret: bytes):
        local_dek = self.orchestrator.dek
        if not local_dek:
            raise ValueError("Vault is locked")
        
        transit_aesgcm = AesGcm(shared_secret)
        dek_iv, dek_encrypted = transit_aesgcm.encrypt_cipherstream(local_dek)


        with self.orchestrator.io_lock:
            self.orchestrator.sync_map_to_disc()
            base_filename = os.path.splitext(os.path.basename(self.orchestrator.filepath))[0]
            transit_path = os.path.join(tempfile.gettempdir(), f"{base_filename}.tmp")
            shutil.copy2(self.filepath, transit_path)

        with open(transit_path, 'r+b') as tfile:
            tfile.seek(0)
            magic_num = struct.pack('>4s', b"TRAN")
            tfile.write(magic_num)
            tfile.seek(23)
            tfile.write(dek_iv + dek_encrypted)
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
            kdf = MfaKdf(existing_salt=salt)
            kek = bytearray(kdf.derive(new_mp, new_wp))

            local_aesgcm = AesGcm(kek)
            ndek_iv, ndek_cipher = local_aesgcm.encrypt_cipherstream(dek)

            tfile.seek(7)
            tfile.write(salt)

            tfile.seek(23)
            tfile.write(ndek_iv + ndek_cipher)

            tfile.seek(0)
            tfile.write(b"SCAF")
            os.fsync(tfile.fileno())
        
        shutil.move(received_tmp_path, final_dest_path)
        dek[:] = b'\x00' * len(dek)
        kek[:] = b'\x00' * len(kek)
        return True

    def _generate_file_list(self, active_file_ids: list):
        for file_id in active_file_ids:
            uuid, v_ts = VaultMap.uuid_time(file_id) 
            chunks = self.orchestrator.hashmap.get_meta(uuid, v_ts) 
            for chunk in chunks:
                yield (file_id, chunk['iv'], chunk['start'], chunk['end'])
    
    def _transfer_reencrypt_chunks(self, arguments: tuple):
        file_id, iv, start, end = arguments
        chunk_ct = self.vaultio.read_cargo(start, end)
        chunk_pt = bytearray(self.decrypt_aesgcm.decrypt_cipherstream(iv, chunk_ct))
        n_iv, n_chunk_ct = self.encrypt_aesgcm.encrypt_cipherstream(chunk_pt)
        chunk_pt[:] = b'\x00' * len(chunk_pt)
        return (file_id, n_iv, n_chunk_ct)
    
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
        old_kek = bytearray(32)
        old_dek = bytearray(32)
        new_kek = bytearray(32)
        new_dek = bytearray(32)
        #==================================
        success = False
        try:
            #authenticate & extract old key
            __, _, _, _, current_salt = self.vaultio.read_header()
            kdf = MfaKdf(existing_salt=current_salt)
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
            self.encrypt_aesgcm = AesGcm(new_dek)
            self.decrypt_aesgcm = AesGcm(old_dek)
            #==================================
            new_kek_aes = AesGcm(new_kek)
            n_dek_iv, n_dek_cipher = new_kek_aes.encrypt_cipherstream(new_dek)
            #==================================
            full_db_metadata = self.orchestrator.vaultdb.get_complete_meta()
            file_id_list = self.orchestrator.hashmap.get_all_file_ids()
            new_map_dict = {file_id: [] for file_id in file_id_list}
            #==================================
            with self.orchestrator.io_lock:
                __, major, minor, patch, _ = self.vaultio.read_header()
                version_str = f"{major}.{minor}.{patch}"

                map_identifier_iv = os.urandom(12)
                P, L = 127, 0
                map_identifier_pt = struct.pack('>QQ', P, L)
                map_identifier_iv, map_identifier_ct = self.encrypt_aesgcm.encrypt_cipherstream(map_identifier_pt, map_identifier_iv)
                
                self.tmpvaultio.initialize_new_vault(
                    version_str, 
                    new_salt, 
                    n_dek_iv, 
                    n_dek_cipher,
                    map_identifier_iv,
                    map_identifier_ct   
                )
                #==================================
                #mutli-threading encryption and writing
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    mapper = executor.map(self._transfer_reencrypt_chunks, self._generate_file_list(file_id_list))
                    for file_id, iv, ciphertext in mapper:
                        start = self.tmpvaultio.get_eof()
                        end = start + len(ciphertext)
                        
                        self.tmpvaultio.append_cargo(ciphertext)
                        new_map_dict[file_id].append({
                            "iv": iv,
                            "start": start,
                            "end": end
                        })
                #==================================
                self.sync_map_to_disc(new_map_dict, full_db_metadata)

                if self.orchestrator.hashmap is not None:
                    self.orchestrator.hashmap.destroy()
                    self.orchestrator.hashmap = None

                self.orchestrator.dek[:] = new_dek
                if hasattr(self.orchestrator, 'ledger') and self.orchestrator.ledger:
                    self.orchestrator.ledger.dek[:] = new_dek
                os.replace(self.tmp_path, self.filepath)

                success = True

                
        #==================================
        #wiping shit from memory
        finally:
            #rollback delte temp file only if the rotation failed
            if not success and os.path.exists(self.tmp_path):
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
    
    def stream_transit_vault(self, transit_path: str, chunk_size: int = 2*1024*1024):
        """Uses VaultIO to yield the transit file in memory-safe chunks."""
        for chunk in VaultIO.yield_cargo(transit_path, chunk_size):
            yield chunk

    def receive_transit_vault(self, transit_path: str, chunk_generator):
        """Receives a full vault stream from the network and writes it via VaultIO."""
        VaultIO.write_cargo(transit_path, chunk_generator)

    
    def execute_self_destruct(self):
        try:
            with self.orchestrator.io_lock:
                #wipe the salt, lockbox and some data
                with open(self.filepath, 'r+b') as f:
                    f.seek(0)
                    f.write(b'\x00' * 127)
                    filesize = os.path.getsize(self.filepath)
                    for _ in range(100):
                        start_pos = random.randint(127, max(127, filesize - 1))
                        # Determine a safe wipe length that doesn't artificially extend the file size
                        wipe_len = random.randint(250, 500)
                        safe_wipe_len = min(wipe_len, filesize - start_pos)
                        f.seek(start_pos)
                        f.write(b'\x00' * safe_wipe_len)
                os.remove(self.filepath)
                if self.orchestrator.ledger and os.path.exists(self.orchestrator.ledger.ledger_path):
                    os.remove(self.orchestrator.ledger.ledger_path)
                    
            print("[*] Vault destroyed. Goodbye.")
        except Exception:
            pass
        finally:
            os._exit(1) #forcekill python instantly