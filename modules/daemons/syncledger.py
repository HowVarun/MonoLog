import os
import msgpack
import time
from modules.crypto_core import AesGcm

class WrongFileError(Exception):
    pass
    
class SyncLedger:
    ACTION_DELETE = 0
    ACTION_RENAME = 1
    ACTION_EDIT = 2 
    ACTION_INGEST = 3

    def __init__(self, ledger_path: str, dek: bytes, retention=30 ):
        self.ledger_path = ledger_path 
        self.dek = bytearray(dek)
        self.ledger = []
        self.retention = retention*86400
        self._boot()
    
    @property
    def ledger_path(self):
        return self._filepath
    
    @ledger_path.setter
    def ledger_path(self, path):
        # Allow paths for new vaults where the file does not exist on disk yet
        if os.path.splitext(os.path.basename(path))[1] == '.enc':
            self._filepath = path
        else:
            raise WrongFileError("Ledger must be an .enc file")
        
    def _boot(self):
        if not os.path.exists(self._filepath):
            self.ledger = []
            return
            
        local_aesgcm = AesGcm(self.dek)
        with open(self._filepath, 'rb') as f:
            iv = f.read(12)
            ciphertext = f.read()
            
        file_bytes = local_aesgcm.decrypt_cipherstream(iv, ciphertext)
        ledger = msgpack.unpackb(file_bytes, raw=False)
        current_time = int(time.time())
        
        self.ledger = [row for row in ledger
                       if row[3] == 0 or (current_time - row[3]) <= self.retention]
            
    def append_event(self, uuid: bytes, v_ts: int, action: int):
        self.ledger.append([uuid, v_ts, action, 0])
    
    def mark_synced(self, uuid: bytes, highest_v_ts: int):
        sync_time = int(time.time())
        for record in self.ledger:
            if record[0] == uuid and record[1] <= highest_v_ts and record[3] == 0:
                record[3] = sync_time
    
    def _action_manager(self, prev_action: int, curr_action: int) -> int:
        if curr_action == self.ACTION_DELETE:
            return self.ACTION_DELETE
            
        # Heavy data pulls (EDIT/INGEST) swallow lighter metadata renames
        if curr_action in (self.ACTION_EDIT, self.ACTION_INGEST):
            return curr_action
            
        if curr_action == self.ACTION_RENAME:
            if prev_action in (self.ACTION_EDIT, self.ACTION_INGEST):
                return prev_action
            if prev_action == self.ACTION_DELETE:
                return self.ACTION_DELETE
            return self.ACTION_RENAME
            
        return curr_action

    def get_unsynced_payload(self):
        unsynced = {}
        for record in self.ledger:
            if record[3] == 0:
                uuid = record[0]
                v_ts = record[1]
                action = record[2]
                
                if uuid not in unsynced:
                    unsynced[uuid] = [v_ts, action]
                else:
                    unsynced[uuid][0] = v_ts
                    prev_action = unsynced[uuid][1]
                    unsynced[uuid][1] = self._action_manager(prev_action, action)
        return unsynced

    def get_ledger(self):
        if not self.ledger:
            return []
        
        return [(record[0], record[1], record[2]) for record in self.ledger]
    
    
    def close(self):
        pt = msgpack.packb(self.ledger, use_bin_type=True)
        iv, ciphertext = AesGcm(self.dek).encrypt_cipherstream(pt)
        
        # Write to temporary file first to prevent corruption during sudden power loss
        tmp_path = self._filepath + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(iv + ciphertext)
        os.replace(tmp_path, self._filepath)
        
        self.ledger.clear()
        self.ledger = None
        
        # Zero-trace wiping of DEK in memory
        if self.dek:
            self.dek[:] = b'\x00' * len(self.dek)