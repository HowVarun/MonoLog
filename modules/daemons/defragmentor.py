import os
import struct
import threading
import concurrent.futures

from modules.system import VaultIO
from modules.vaultmap import VaultMap
from modules.crypto_core import AesGcm 

class Defragmentation:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.vaultdb = orchestrator.vaultdb
        self.hashmap = orchestrator.hashmap
        self.vaultio = orchestrator.vaultio
        self.filepath = orchestrator.filepath
        self.tmp_path = self.filepath + ".tmp"

        self.hashmapt = VaultMap()
        self.is_running = False
        self.read_lock = threading.Lock()

    def _active_chunk_generator(self, active_files: list):
        for uuid, v_ts in active_files:
            chunks = self.hashmap.get_meta(uuid, v_ts)
            for chunk in chunks:
                yield (
                    uuid,
                    v_ts,
                    chunk['iv'],
                    chunk['start'],
                    chunk['end']
                )
    
    def _transfer_chunks(self, arguments: tuple):
        uuid, v_ts, iv, start, end = arguments
        chunk_ct = self.vaultio.read_cargo(start, end)
            
        return (uuid, v_ts, iv, chunk_ct)

    def sync_map_to_disc(self, new_map_dict: dict, tmp_vaultio: VaultIO):
        local_aesgcm = AesGcm(self.orchestrator.dek)
        
        temp_hashmap = VaultMap()
        temp_hashmap.map = new_map_dict
        
        nmap = self.vaultdb.get_complete_meta()
        nmap_pt = temp_hashmap.restitch(nmap)
        
        nmap_iv, nmap_ciphertext = local_aesgcm.encrypt_cipherstream(nmap_pt)
        nmap_P = tmp_vaultio.get_eof()
        nmap_L = len(nmap_iv) + len(nmap_ciphertext)
        tmp_vaultio.append_map(nmap_iv, nmap_ciphertext)

        identifier_pt = struct.pack('>QQ', nmap_P, nmap_L)
        iv_identifier, identifier_ct = local_aesgcm.encrypt_cipherstream(identifier_pt)

        tmp_vaultio.write_pointer(iv_identifier, identifier_ct)

    def vacuum(self):
        if self.is_running:
            return False
        self.is_running = True
        try:
            with self.orchestrator.io_lock:
                active_files = self.orchestrator.vaultdb.get_active_files()
                new_map_dict = {self.hashmap.fileid(uuid, v_ts): [] for uuid, v_ts in active_files}

                with open(self.tmp_path, 'wb') as wfile, open(self.orchestrator.filepath, 'rb') as rfile:
                    data = rfile.read(127)
                    wfile.write(data)

                tmp_vaultio = VaultIO(self.tmp_path)

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    mapper = executor.map(
                        self._transfer_chunks,
                        self._active_chunk_generator(active_files)
                    )
                    for uuid, v_ts, iv, ciphertext in mapper:
                        start = tmp_vaultio.get_eof()
                        end = start + len(ciphertext)
                        tmp_vaultio.append_cargo(ciphertext)
                        
                        _fileid = self.hashmap.fileid(uuid, v_ts)
                        new_map_dict[_fileid].append({
                            "iv": iv,
                            "start": start,
                            "end": end
                        })

                if hasattr(self.vaultdb, 'purge_inactive_files'):
                    self.vaultdb.purge_inactive_files()
                    
                self.sync_map_to_disc(new_map_dict, tmp_vaultio)
                
                os.replace(self.tmp_path, self.filepath)
                self.hashmap.map = new_map_dict
                return True
        finally:
            self.is_running = False
            if os.path.exists(self.tmp_path):
                try:
                    os.remove(self.tmp_path)
                except OSError:
                    pass