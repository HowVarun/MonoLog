import os
import time
import struct
import concurrent.futures
import threading
import portalocker
import tempfile

from modules.crypto_core import MfaKdf, AesGcm, hashing
from modules.vaultmap import VaultMap, VaultDatabase
from modules.system import VaultIO, GhostFileIO, IDGenerator, TransferProgress
from modules.daemons import SyncLedger

class VaultManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.ledgerpath = os.path.splitext(self.filepath)[0] + ".enc"
        self.vaultio = VaultIO(self.filepath)
        #==================================
        self.io_lock = threading.RLock()
        #==================================
        self.progress = TransferProgress()
        self.lock_filepath = self.filepath + ".lock"
        self.os_lock_handle = open(self.lock_filepath, 'w')
        try:
            portalocker.lock(self.os_lock_handle, portalocker.LOCK_EX | portalocker.LOCK_NB)
            
            self.os_lock_handle.write("Your Vault is locked by Secure Vault")
            self.os_lock_handle.flush()

        except portalocker.exceptions.LockException:
            self.os_lock_handle.close()
            raise PermissionError("This vault is already open in another process")

    # Category 1 : Lifecycle and Authentication

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
        self.ledger = SyncLedger(self.ledgerpath, self.dek)


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

        #CHECK 1 :
        if self.vaultio.read_header()[0] != b'SCAF':
            raise ValueError("Not a valid SCAF File")
        else:
            None
        
        local_aesgcm = AesGcm(self.dek)
        iv_identifier, identifier_ct = self.vaultio.read_pointer()
        identifier_pt = local_aesgcm.decrypt_cipherstream(iv_identifier, identifier_ct)
        P, L = struct.unpack(">QQ", identifier_pt)
        if L == 0:
            self.hashmap = VaultMap()
            self.vaultdb = VaultDatabase()
            self.ledger = SyncLedger(self.ledgerpath, self.dek)
        else:
            map_cipher = self.vaultio.read_map(P,L)
            map_iv = map_cipher[:12]
            map_cipher = map_cipher[12:]
            map_pt = local_aesgcm.decrypt_cipherstream(map_iv, map_cipher)
            self.hashmap = VaultMap()
            self.vaultdb = VaultDatabase()
            self.vaultdb.db_map_sync(self.hashmap.stitch(map_pt))
            self.ledger = SyncLedger(self.ledgerpath, self.dek)
            del map_pt

    def lock_vault(self):
        with self.io_lock:  
            if hasattr(self, 'hashmap') and self.hashmap is not None:
                self.sync_map_to_disc()
                self.hashmap.destroy()
                del self.hashmap
            
            if hasattr(self, 'vaultdb') and self.vaultdb is not None: 
                self.vaultdb.close_connection()
                del self.vaultdb
        
            if hasattr(self, 'os_lock_handle'):  
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
                
            if hasattr(self, 'ledger') and self.ledger is not None:
                self.ledger.close()
                del self.ledger
                
            if hasattr(self, 'dek') and self.dek:
                self.dek[:] = b'\x00' * len(self.dek)
                del self.dek

    # Category 2 : Data Modification (Ingest, Rename, Delete)

    def _chunked_coordinates(self, filepath :str, chunk_io : int = 2*1024*1024):
        filesize = os.path.getsize(filepath)
        for offset in range(0, filesize, chunk_io):  
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
            
            # Patch structural mismatch between DB ('uuid') and HashMap ('file_id')
            for row in nmap:
                if 'uuid' in row and 'file_id' not in row:
                    row['file_id'] = row['uuid']
                    
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

    def ingest_file(self, os_filepath, virtual_filepath = None, existing_uuid: bytes = None, existing_v_ts: int = None, override_v_ts : int = None):
        if not os.path.exists(os_filepath):
            raise FileNotFoundError(f"Cannot ingest missing file: {os_filepath}")
        filesize = os.path.getsize(os_filepath)
        new_v_ts = override_v_ts if override_v_ts else int(time.time())
        chunk_metadata = []
        
        
            
        
        chunk_generator = self._chunked_coordinates(os_filepath)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            mapper = executor.map(self._worker_encrypt, chunk_generator)
            with self.io_lock:
                ##########################################
                if existing_uuid and existing_v_ts:  
                    uuid = existing_uuid
                    action = self.ledger.ACTION_EDIT
                    
                    old_meta = self.vaultdb.get_meta(uuid, existing_v_ts)
                    if not old_meta:
                        raise FileNotFoundError("Active file metadata not found for edit")
                    original_created_at = old_meta["created_at"]
                    if not virtual_filepath:
                        virtual_filepath = old_meta["virtual_path"]
                    self.vaultdb.delete_file(uuid, existing_v_ts, new_v_ts)
                else:
                    uuid = IDGenerator.generate_file_id()
                    action = self.ledger.ACTION_INGEST
                    original_created_at = new_v_ts
                ##########################################
                for iv, ciphertext in mapper:
                    start_byte = self.vaultio.get_eof()
                    end_byte = start_byte + len(ciphertext)
                    self.vaultio.append_cargo(ciphertext)
                    chunk_metadata.append({
                        "iv" : iv,
                        "start" : start_byte,
                        "end" : end_byte        
                    })
                
                self.hashmap.add_file(uuid, new_v_ts, chunk_metadata)
                
                meta_dict = {
                    "size_bytes" : filesize,
                    "created_at" : original_created_at, 
                    "is_active" : True
                }
                self.vaultdb.inmo_file(uuid, new_v_ts, virtual_filepath, meta_dict)
                self.ledger.append_event(uuid, new_v_ts, action)

                self.sync_map_to_disc()
                    
    def delete_file(self, uuid: bytes, v_ts: int, override_v_ts: int = None):
        with self.io_lock:
            delete_ts = override_v_ts if override_v_ts else int(time.time())

            chunks = self.hashmap.get_meta(uuid, v_ts)
            self.hashmap.add_file(uuid, delete_ts, chunks)
            
            self.vaultdb.delete_file(uuid, v_ts, delete_ts)
            self.ledger.append_event(uuid, delete_ts, self.ledger.ACTION_DELETE,)   
            self.sync_map_to_disc()
            
    def rename_file(self, uuid: bytes, v_ts: int, new_virtual_path: str, override_v_ts: int = None):
        with self.io_lock:
            new_v_ts = override_v_ts if override_v_ts else int(time.time())
            
            old_meta = self.vaultdb.get_meta(uuid, v_ts)
            if not old_meta:
                raise FileNotFoundError("Original file metadata not found")
                
            safe_path = self.vaultdb.assign_name(new_virtual_path)
            
            self.vaultdb.delete_file(uuid, v_ts, new_v_ts)
            
            meta_dict = {
                "size_bytes": old_meta["size_bytes"],
                "created_at": old_meta["created_at"],
                "is_active": True
            }
            self.vaultdb.inmo_file(uuid, new_v_ts, safe_path, meta_dict)
            
            chunks = self.hashmap.get_meta(uuid, v_ts)
            self.hashmap.add_file(uuid, new_v_ts, chunks)
            
            self.ledger.append_event(uuid, new_v_ts, self.ledger.ACTION_RENAME)              
            self.sync_map_to_disc()

    def ingest_network_payload(self, tmp_filepath: str, virtual_filepath: str, uuid: bytes, remote_v_ts: int, local_v_ts: int, incoming_hashmap: list, created_at: int = None):
        try:
            with self.io_lock:
                filesize = os.path.getsize(tmp_filepath)
                chunk_metadata = []
                
                # 1. Read already-encrypted chunks via VaultIO and append to vault cargo
                for chunk in incoming_hashmap:
                    ciphertext = self.vaultio.read_external_chunk(tmp_filepath, chunk["start"], chunk["end"])
                    
                    start_byte = self.vaultio.get_eof()
                    end_byte = start_byte + len(ciphertext)
                    self.vaultio.append_cargo(ciphertext)
                    
                    chunk_metadata.append({
                        "iv": chunk["iv"],
                        "start": start_byte,
                        "end": end_byte
                    })
                
                # 2. Update DB & Hashmap
                if local_v_ts > 0:
                    action = self.ledger.ACTION_EDIT
                    old_meta = self.vaultdb.get_meta(uuid, local_v_ts)
                    original_created_at = old_meta["created_at"] if old_meta else (created_at or remote_v_ts)
                    self.vaultdb.delete_file(uuid, local_v_ts, remote_v_ts)
                    safe_path = virtual_filepath if (old_meta and old_meta["virtual_path"] == virtual_filepath) else self.vaultdb.assign_name(virtual_filepath)
                else:
                    action = self.ledger.ACTION_INGEST
                    original_created_at = created_at or remote_v_ts
                    safe_path = self.vaultdb.assign_name(virtual_filepath)

                self.hashmap.add_file(uuid, remote_v_ts, chunk_metadata)
                
                meta_dict = {
                    "size_bytes": filesize,
                    "created_at": original_created_at,
                    "is_active": True
                }
                
                self.vaultdb.inmo_file(uuid, remote_v_ts, safe_path, meta_dict)
                self.ledger.append_event(uuid, remote_v_ts, action)               
                self.sync_map_to_disc()

        finally:
            if os.path.exists(tmp_filepath):
                try:
                    os.remove(tmp_filepath)
                except OSError:
                    pass
    
    # Category 3 : Extraction (Stream, Preview, Restore)
    
    def _worker_decrypt(self, chunk_dict : dict):
        local_aesgcm = AesGcm(self.dek)
        iv = chunk_dict.get('iv') 
        start = chunk_dict.get('start')
        end = chunk_dict.get('end')
        ciphertext = self.vaultio.read_cargo(start, end)
        plaintext = local_aesgcm.decrypt_cipherstream(iv, ciphertext)
        return plaintext

    def stream_file(self, uuid: bytes, v_ts: int):
        chunk_array = self.hashmap.get_meta(uuid, v_ts)
        if not chunk_array:
            raise FileNotFoundError(f"File ID {uuid.hex()} at {v_ts} not found in your hashmap")
            
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for plaintext_chunk in executor.map(self._worker_decrypt, chunk_array):
                yield plaintext_chunk

    def preview_file(self, uuid: bytes, v_ts: int):
        meta = self.vaultdb.get_meta(uuid, v_ts)
        if not meta:
            raise FileNotFoundError("Metadata missing for requested preview")
        
        virtual_path = meta['virtual_path']
        self.ghostfile = GhostFileIO()
        ghost_path = self.ghostfile.create_ghost_path(virtual_path)
        
        for plaintext_chunk in self.stream_file(uuid, v_ts):
            self.ghostfile.write_decrypted_chunk(ghost_path, plaintext_chunk)
        self.ghostfile.launch_file(ghost_path)

    def restore_version(self, uuid: bytes, active_v_ts: int, archived_v_ts: int):
        with self.io_lock:
            archived_meta = self.vaultdb.get_meta(uuid, archived_v_ts)
            archived_chunks = self.hashmap.get_meta(uuid, archived_v_ts)
            
            if not archived_meta or not archived_chunks:
                raise FileNotFoundError(f"Archived data missing for UUID {uuid.hex()[:8]}")

            
            if active_v_ts > 0:
                self.vaultdb.delete_file(uuid, active_v_ts, delete_ts=int(time.time()))

            # 2. Duplicate chunks directly (No decryption needed, identical DEK!)
            new_v_ts = int(time.time()) + 1 # +1 ensures strictly newer than delete_ts
            new_chunks = []
            
            for chunk in archived_chunks:
                raw_ct = self.vaultio.read_cargo(chunk['start'], chunk['end'])
                start_byte = self.vaultio.get_eof()
                end_byte = start_byte + len(raw_ct)
                
                self.vaultio.append_cargo(raw_ct)
                new_chunks.append({
                    "iv": chunk['iv'],
                    "start": start_byte,
                    "end": end_byte
                })

            # 3. Save to DB and Hashmap
            self.hashmap.add_file(uuid, new_v_ts, new_chunks)
            
            meta_dict = {
                "size_bytes": archived_meta['size_bytes'],
                "created_at": archived_meta['created_at'],
                "is_active": True
            }
            
            # Strip '.del_' suffix if present, and assign safe name to avoid overwrites
            base_name = archived_meta['virtual_path'].split('.del_')[0]
            safe_path = self.vaultdb.assign_name(base_name)
            
            self.vaultdb.inmo_file(uuid, new_v_ts, safe_path, meta_dict)
            self.ledger.append_event(uuid, new_v_ts, self.ledger.ACTION_EDIT)
            self.sync_map_to_disc()
            return new_v_ts

    def reingest_edit(self, ghost_filepath: str, original_hash: bytes, original_mtime: float, original_size: int, uuid: bytes, active_v_ts: int, ghost_io):
        try:
            if not os.path.exists(ghost_filepath):
                print(f"\n[-] Ghost Edit Failed: Temp file not found at {ghost_filepath}")
                return False

            current_size = os.path.getsize(ghost_filepath)
            current_mtime = os.path.getmtime(ghost_filepath)
            
            with open(ghost_filepath, 'rb') as f:
                current_hash = hashing.hash_key(f.read())

            is_changed = hashing.hash_verify(current_hash, original_hash) or (current_size != original_size) or (current_mtime > original_mtime)

            if is_changed:
                old_meta = self.vaultdb.get_meta(uuid, active_v_ts)
                v_path = old_meta["virtual_path"] if old_meta else "/edited_file"
                print(f"\n[*] Changes detected in [{v_path}]! (Hash/Size/Time modified)")
                print("[*] Re-ingesting into Vault...")
                self.ingest_file(
                    os_filepath=ghost_filepath,
                    virtual_filepath=v_path,
                    existing_uuid=uuid,
                    existing_v_ts=active_v_ts
                )
                print("[+] File updated successfully!")
                return True
            else:
                print("\n[*] No changes detected in Ghost File (Hash, Size, and Time are identical).")
                return False
        finally:
            ghost_io.secure_shred(ghost_filepath)

    def download_temp_file(self, chunk_generator, storage_dir: str) -> str:
            
        fd, tmp_path = tempfile.mkstemp(dir=storage_dir)
        os.close(fd) # Close OS descriptor so VaultIO can open it safely
        VaultIO.write_cargo(tmp_path, chunk_generator)
        return tmp_path

    def fork_conflicted_copy(self, uuid: bytes, active_v_ts: int):
        with self.io_lock:
            old_meta = self.vaultdb.get_meta(uuid, active_v_ts)
            old_chunks = self.hashmap.get_meta(uuid, active_v_ts)
            if not old_meta or not old_chunks:
                return

            stem, ext = os.path.splitext(old_meta['virtual_path'])
            conflict_path = self.vaultdb.assign_name(f"{stem} (Conflicted Copy){ext}")
            
            new_uuid = IDGenerator.generate_file_id()
            fork_ts = int(time.time())
            new_chunks = []

            # Copy raw encrypted chunks to EOF under the new UUID
            for chunk in old_chunks:
                raw_ct = self.vaultio.read_cargo(chunk['start'], chunk['end'])
                start_byte = self.vaultio.get_eof()
                end_byte = start_byte + len(raw_ct)
                self.vaultio.append_cargo(raw_ct)
                new_chunks.append({
                    "iv": chunk['iv'],
                    "start": start_byte,
                    "end": end_byte
                })

            meta_dict = {
                "size_bytes": old_meta['size_bytes'],
                "created_at": old_meta['created_at'],
                "is_active": True
            }
            self.hashmap.add_file(new_uuid, fork_ts, new_chunks)
            self.vaultdb.inmo_file(new_uuid, fork_ts, conflict_path, meta_dict)
            self.ledger.append_event(new_uuid, fork_ts, self.ledger.ACTION_INGEST)
            self.sync_map_to_disc()