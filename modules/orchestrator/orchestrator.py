import os
import time
import struct
import concurrent.futures
import threading
import portalocker

from modules.crypto_core import MfaKdf, AesGcm
from modules.vaultmap import VaultMap, VaultDatabase
from modules.system import VaultIO, GhostFileIO

class VaultManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.vaultio = VaultIO(self.filepath)
        #==================================
        self.io_lock = threading.RLock()
        #==================================
        self.lock_filepath = self.filepath + ".lock"
        self.os_lock_handle = open(self.lock_filepath, 'w')
        try:
            portalocker.lock(self.os_lock_handle, portalocker.LOCK_EX | portalocker.LOCK_NB) #<--------------- portalocker
            
            self.os_lock_handle.write("Your Vault is locked by Secure Vault")
            self.os_lock_handle.flush()

        except portalocker.exceptions.LockException:
            self.os_lock_handle.close()
            raise PermissionError("This vault is already open in another process")
        #==================================

    #Category 1 : Lifecycle and Authentication

    def create_new_vault(self, master_pass, weak_pass):
        if os.path.exists(self.filepath):
            raise FileExistsError("File already exists!")
        #==================================
        salt = os.urandom(16)
        kdf = MfaKdf(existing_salt = salt)
        self.kek_hash = bytearray(kdf.derive(master_pass, weak_pass))
        #==================================
        self.dek = bytearray(os.urandom(32))
        dek_aesgcm = AesGcm(self.kek_hash)
        dek_iv, encrypted_dek = dek_aesgcm.encrypt_cipherstream(self.dek)
        #==================================
        local_aesgcm = AesGcm(self.dek)
        map_identifier_iv = os.urandom(12)
        P, L = 127, 0
        map_identifier_pt = struct.pack('>QQ', P, L)
        _, map_identifier_ct = local_aesgcm.encrypt_cipherstream(map_identifier_pt, map_identifier_iv)
        #==================================
        self.vaultio.initialize_new_vault("1.0.0", salt, dek_iv, encrypted_dek, map_identifier_iv, map_identifier_ct)
        salt, map_identifier_iv, map_identifier_ct = b"", b"", b""
        self.hashmap = VaultMap()
        self.vaultdb = VaultDatabase()
        #==================================


    def unlock_hash(self, master_password, weak_password):
        self.check, self.major, self.minor, self.patch, self.salt = self.vaultio.read_header()
        #==================================
        kdf = MfaKdf(existing_salt = self.salt)
        self.kek_hash = bytearray(kdf.derive(master_password, weak_password))
        #==================================
        dek_iv, encrypted_dek = self.vaultio.read_lockbox()
        dek_aesgcm = AesGcm(self.kek_hash)
        self.dek = bytearray(dek_aesgcm.decrypt_cipherstream(dek_iv, encrypted_dek))


    def boot_vault(self):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError("Vault does not exist!")
        
        local_aesgcm = AesGcm(self.dek)
        iv_identifier, identifier_ct = self.vaultio.read_pointer()
        identifier_pt = local_aesgcm.decrypt_cipherstream(iv_identifier, identifier_ct)
        P, L = struct.unpack(">QQ", identifier_pt)
        if L == 0:
            self.hashmap = VaultMap()
            self.vaultdb = VaultDatabase()
        else:
            map_cipher = self.vaultio.read_map(P,L)
            map_iv = map_cipher[:12]
            map_cipher = map_cipher[12:]
            map_pt = local_aesgcm.decrypt_cipherstream(map_iv, map_cipher)
            self.hashmap = VaultMap()
            self.vaultdb = VaultDatabase()
            self.vaultdb.db_map_sync(self.hashmap.stitch(map_pt))
            del map_pt

    def lock_vault(self):
        with self.io_lock:  #Delete Hashmap
            if hasattr(self, 'hashmap') and self.hashmap is not None:
                self.sync_map_to_disc()
                self.hashmap.destroy()
                del self.hashmap
            
            if hasattr(self, 'vaultdb') and self.vaultdb is not None: #Delete Database
                self.vaultdb.close_connection()
                del self.vaultdb
        
            if hasattr(self, 'os_lock_handle'):  #Delete Manager lock and Re-enable access
                portalocker.unlock(self.os_lock_handle)
                self.os_lock_handle.close()
                if os.path.exists(self.lock_filepath):
                    try:
                        os.remove(self.lock_filepath)
                    except OSError:
                        pass
            if hasattr(self, 'kek_hash') and self.kek_hash:
                self.kek_hash[:] = b'\x00' * len(self.kek_hash)
                del self.kek_hash
                
            if hasattr(self, 'dek') and self.dek:
                self.dek[:] = b'\x00' * len(self.dek)
                del self.dek

    #Category 2 : Ingestion

    def _chunked_coordinates(self, filepath :str, chunk_io : int = 2*1024*1024):
        filesize = os.path.getsize(filepath)
        for offset in range(0, filesize, chunk_io):  #start with 0 read 0 then read chunk_io 
            size = min(chunk_io, filesize - offset)
            yield (filepath, offset, size)

    
    def _worker_encrypt(self, chunked_coordinates : tuple):
        chunk_io = 2*1024*1024
        filepath, offset, size = chunked_coordinates
        local_aesgcm = AesGcm(self.dek)
        with open(filepath, 'rb') as f:
            f.seek(offset)
            pt_chunk = f.read(size)
        iv, ciphertext = local_aesgcm.encrypt_cipherstream(pt_chunk)
        return iv, ciphertext
    
    def sync_map_to_disc(self):
        with self.io_lock:
            local_aesgcm = AesGcm(self.dek)
            nmap = self.vaultdb.get_complete_meta()
            nmap_pt = self.hashmap.restitch(nmap)
            nmap_iv, nmap_ciphertext = local_aesgcm.encrypt_cipherstream(nmap_pt)
            nmap_P = self.vaultio.get_eof()
            nmap_L =  len(nmap_iv) + len(nmap_ciphertext)
            identifier_pt = struct.pack('>QQ', nmap_P, nmap_L)
            iv_identifier, identifier_ct = local_aesgcm.encrypt_cipherstream(identifier_pt)
            map_pointer_iv, map_pointer_cipher = self.vaultio.read_pointer()
            map_pointer_pt = local_aesgcm.decrypt_cipherstream(map_pointer_iv, map_pointer_cipher)
            map_P, map_L = struct.unpack('>QQ', map_pointer_pt)
            self.vaultio.atomic_map_swap(iv_identifier, identifier_ct, nmap_P, nmap_iv, nmap_ciphertext)

    def ingest_file(self, os_filepath, virtual_filepath):
        filesize = os.path.getsize(os_filepath)
        created_at = int(time.time())
        chunk_metadata = []
        if os.path.exists(os_filepath):
            chunk_generator = self._chunked_coordinates(os_filepath)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                mapper = executor.map(self._worker_encrypt, chunk_generator)
                with self.io_lock:
                    for iv, ciphertext in mapper:
                        start_byte = self.vaultio.get_eof()
                        end_byte = start_byte + len(ciphertext)
                        self.vaultio.append_cargo(ciphertext)
                        chunk_metadata.append({
                            "iv" : iv,
                            "start" : start_byte,
                            "end" : end_byte        
                        })
                    self.hashmap.add_file(virtual_filepath, chunk_metadata)
                    meta_dict = {
                        "size_bytes" : filesize,
                        "created_at" : created_at,
                        "is_active" : True
                    }
                    self.vaultdb.inmo_file(virtual_filepath, meta_dict)
                    self.sync_map_to_disc()
    
    #Category 3 : Extraction
    def _worker_decrypt(self, chunk_dict : dict):
        #This worker recieves one input dictionary we decrypt one chunk
        #{iv : 12bytes, start: int, end : int}
        local_aesgcm = AesGcm(self.dek)
        iv = chunk_dict.get('iv') 
        start = chunk_dict.get('start')
        end = chunk_dict.get('end')
        ciphertext = self.vaultio.read_cargo(start, end)
        plaintext = local_aesgcm.decrypt_cipherstream(iv, ciphertext)
        return plaintext

    def stream_file(self, virtual_path : str):
        chunk_array = self.hashmap.get_meta(virtual_path)
        if not chunk_array:
            raise FileNotFoundError(f"{virtual_path} not found in your map")
        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for plaintext_chunk in executor.map(self._worker_decrypt, chunk_array):
                    yield plaintext_chunk

    def preview_file(self, virtual_path : str):
        self.ghostfile = GhostFileIO()
        ghost_path = self.ghostfile.create_ghost_path(virtual_path)
        for plaintext_chunk in self.stream_file(virtual_path):
            self.ghostfile.write_decrypted_chunk(ghost_path, plaintext_chunk)
        self.ghostfile.launch_file(ghost_path)

    def restore_version(self, virtual_path: str, timestamp_search: int):
        with self.io_lock:
            timestamp_set = int(time.time())
            delete_path = f"{virtual_path}.del_{timestamp_search}"
            archive_path = f"{virtual_path}.del_{timestamp_set}"
            
            self.vaultdb.restore_file(virtual_path, timestamp_search, timestamp_set)
            
            active_chunks = self.hashmap.map.pop(virtual_path, None)
            historical_chunks = self.hashmap.map.pop(delete_path, None)
            
            if active_chunks is not None:
                self.hashmap.map[archive_path] = active_chunks
                
            if historical_chunks is not None:
                self.hashmap.map[virtual_path] = historical_chunks
            else:
                raise KeyError(f"Critical desync: Backup data stream for '{delete_path}' missing in RAM mapping.")
                
            self.sync_map_to_disc()