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

    def __init__(self, ledger_path: str, dek: bytes):
            self.ledger_path = ledger_path 
            self.dek = bytearray(dek)
            # Schema: { uuid_bytes : [data_v_ts, meta_v_ts, is_deleted] }
            self.ledger = {}
            self._boot()
    
    @property
    def ledger_path(self):
        return self._filepath
    
    @ledger_path.setter
    def ledger_path(self, path: str):
        base = os.path.basename(path)
        stem, ext = os.path.splitext(base)
        if ext == '.enc' and not stem.endswith('.sync'):
            self._filepath = path
        else:
            raise WrongFileError("Ledger must be a direct .enc file (not .sync.enc)")
        
    def _boot(self):
        if not os.path.exists(self._filepath):
            self.ledger = {}
            return
            
        local_aesgcm = AesGcm(self.dek)
        with open(self._filepath, 'rb') as f:
            iv = f.read(12)
            ciphertext = f.read()
            
        file_bytes = local_aesgcm.decrypt_cipherstream(iv, ciphertext)
        ledger = msgpack.unpackb(file_bytes, raw=False, strict_map_key = False)
        #Ensurig dictionary is { uuid: [data_v_ts, meta_v_ts, is_deleted] }
        if isinstance(ledger, dict):
            self.ledger = ledger
        else:
            self.ledger = {}

    def _flush(self):
            if self.ledger is None:
                return
            pt = msgpack.packb(self.ledger, use_bin_type=True)
            iv, ciphertext = AesGcm(self.dek).encrypt_cipherstream(pt)
            
            tmp_path = self._filepath + ".tmp"
            with open(tmp_path, 'wb') as f:
                f.write(iv + ciphertext)
            os.replace(tmp_path, self._filepath)
           
    def append_event(self, uuid: bytes, v_ts: int, action: int):
        existing = self.ledger.get(uuid)
        prev_data_ts = existing[0] if existing else v_ts

        if action in (self.ACTION_INGEST, self.ACTION_EDIT):
            self.ledger[uuid] = [v_ts, v_ts, False]
        elif action == self.ACTION_RENAME:
            self.ledger[uuid] = [prev_data_ts, v_ts, False]
        elif action == self.ACTION_DELETE:
            self.ledger[uuid] = [prev_data_ts, v_ts, True]
        else:
            raise ValueError(f"Unknown SyncLedger action: {action}")
        self._flush()
    
    def mark_synced(self, uuid: bytes, data_ts: int, meta_ts: int, is_del: bool = False):
        self.ledger[uuid] = [data_ts, meta_ts, is_del]
        self._flush()

    def mark_all_synced(self, ml_dsa_hash : bytes):
        #legacy function for compatibility
                pass
    
    def get_unsynced_payload(self):
        return dict(self.ledger)

    def get_ledger(self):
        result = []
        if not self.ledger:
            return result

        for uuid, data in self.ledger.items():
            data_ts, meta_ts, is_del = data
            if is_del:
                final_action = self.ACTION_DELETE
            elif data_ts == meta_ts:
                final_action = self.ACTION_EDIT
            else:
                final_action = self.ACTION_RENAME
            result.append((uuid, meta_ts, final_action, data_ts, is_del))
        return result

    def purge_deleted(self):
        self.ledger = {u: s for u, s in self.ledger.items() if not s[2]}
        self._flush()

        
    def close(self):
        self._flush()
        self.ledger.clear()
        self.ledger = None
        
        # Zero-trace wiping of DEK in memory
        if self.dek:
            self.dek[:] = b'\x00' * len(self.dek)