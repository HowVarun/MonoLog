import os
import struct
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


        self.vaultiot = VaultIO(self.tmp_path)
        self.hashmapt = VaultMap()
        self.is_running = False

    def _active_chunk_generator(self, active_files : list):
        #list of virtual paths that are active
        for virtual_paths in active_files:
            chunks = self.hashmap.get_meta(virtual_paths)
            for chunk in chunks:
                yield (
                    virtual_paths,
                    chunk['iv'],
                    chunk['start'],
                    chunk['end']
                )
    
    def _transfer_chunks(self, arguments : tuple):
        virtual_path, iv, start, end = arguments
        chunk_ct = self.vaultio.read_cargo(start, end)
        return (virtual_path, iv, chunk_ct)

    def sync_map_to_disc(self, new_map_dict: dict):
        local_aesgcm = AesGcm(self.orchestrator.hash)
        
       
        temp_hashmap = VaultMap()
        temp_hashmap.map = new_map_dict
        
        nmap = self.vaultdb.get_complete_meta()
        nmap_pt = temp_hashmap.restitch(nmap)
        
        
        nmap_iv, nmap_ciphertext = local_aesgcm.encrypt_cipherstream(nmap_pt)
        nmap_P = self.vaultiot.get_eof()
        nmap_L = len(nmap_iv) + len(nmap_ciphertext)
        self.vaultiot.append_map(nmap_iv, nmap_ciphertext) 

        identifier_pt = struct.pack('>QQ', nmap_P, nmap_L)
        iv_identifier, identifier_ct = local_aesgcm.encrypt_cipherstream(identifier_pt)

        with open(self.tmp_path, 'r+b') as tmp_file:
            tmp_file.seek(23)
            tmp_file.write(iv_identifier+ identifier_ct)
            os.fsync(tmp_file.fileno())

    def vacuum(self):
        if self.is_running:
            return False
        self.is_running = True
        try:
            with self.orchestrator.io_lock:
                
                active_files = self.orchestrator.vaultdb.get_active_files()
                new_map_dict = {vpath: [] for vpath in active_files}

                with open(self.tmp_path, 'wb') as wfile, open(self.orchestrator.filepath, 'rb') as rfile:
                    data = rfile.read(67)
                    wfile.write(data)

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    mapper = executor.map(
                        self._transfer_chunks,
                        self._active_chunk_generator(active_files)
                        )
                    for virtual_path, iv, ciphertext in mapper:
                        start = self.vaultiot.get_eof()
                        end = start + len(ciphertext)
                        self.vaultiot.append_cargo(ciphertext)
                        new_map_dict[virtual_path].append({
                            "iv" : iv,
                            "start" : start,
                            "end" : end
                        })
    

                if hasattr(self.vaultdb, 'purge_inactive_files'):
                    self.vaultdb.purge_inactive_files()
                self.sync_map_to_disc(new_map_dict)
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