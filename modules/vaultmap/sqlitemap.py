import sqlite3
import os
import struct
import time

class VaultDatabase:
    def __init__(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.cursor = self.db.cursor()
        self._create_schema()
        
    @staticmethod
    def uuid_time(fileid: bytes) -> tuple:
        """Unpacks the 24-byte key into (uuid_bytes, v_ts_int)."""
        return struct.unpack('>16sQ', fileid)

    def db_map_sync(self, vault_map_dict: dict):
        info = []
        for _fileid, meta_data in vault_map_dict.items():
            uuid, v_ts = self.uuid_time(_fileid)
            
            virtual_path = meta_data.get("virtual_path")
            file_name = os.path.basename(virtual_path)
            parent_folder = os.path.dirname(virtual_path) + '/'
            info.append((
                uuid, 
                v_ts, 
                file_name, 
                parent_folder, 
                virtual_path, 
                meta_data.get("size_bytes"), 
                meta_data.get("created_at"), 
                meta_data.get("is_active")
            ))
            
        query = '''
            INSERT OR REPLACE INTO files 
            (uuid, v_ts, filename, parent_folder, virtual_path, size_bytes, created_at, is_active) 
            VALUES (?,?,?,?,?,?,?,?)
        '''
        
        self.cursor.executemany(query, info)
        self.db.commit()

    def _create_schema(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                uuid BLOB,
                v_ts INTEGER NOT NULL,
                filename TEXT NOT NULL,
                parent_folder TEXT NOT NULL,
                virtual_path TEXT NOT NULL,
                size_bytes INTEGER,
                created_at INTEGER,
                is_active BOOLEAN,
                PRIMARY KEY (uuid, v_ts)
            )
        ''')
        
        self.cursor.execute('CREATE INDEX idx_folder ON files(parent_folder)')
        self.cursor.execute('CREATE INDEX idx_path ON files(virtual_path)')
        self.db.commit()

    def assign_name(self, virtual_filepath: str) -> str:
        base_dir = os.path.dirname(virtual_filepath)
        original_filename = os.path.basename(virtual_filepath)
        name, ext = os.path.splitext(original_filename)
        
        new_filepath = virtual_filepath
        counter = 1
        
        while True:
            self.cursor.execute("SELECT 1 FROM files WHERE virtual_path = ? AND is_active = 1", (new_filepath,))
            if not self.cursor.fetchone():
                return new_filepath
            
            new_filename = f"{name} ({counter}){ext}"
            new_filepath = f"{base_dir}/{new_filename}" if base_dir else new_filename
            counter += 1

    def inmo_file(self, uuid: bytes, v_ts: int, virtual_path: str, meta_data: dict):
        '''Insert or Modify file metadata'''
        file_name = os.path.basename(virtual_path)
        relative_dir = os.path.dirname(virtual_path) + '/'

        params = (uuid, v_ts, file_name, relative_dir, virtual_path, meta_data.get("size_bytes"), meta_data.get("created_at"), meta_data.get("is_active"))

        query = '''
            INSERT OR REPLACE INTO files 
            (uuid, v_ts, filename, parent_folder, virtual_path, size_bytes, created_at, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.cursor.execute(query, params)
        self.db.commit()

    def get_files_in_folder(self, folder_path: str):
        if not folder_path.endswith('/'):
            folder_path += '/'
        query = 'SELECT uuid, v_ts, filename, size_bytes, created_at FROM files WHERE parent_folder = ? AND is_active = 1'
        self.cursor.execute(query, (folder_path,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def delete_file(self, uuid: bytes, v_ts: int, delete_timestamp: int):
        current_meta = self.get_meta(uuid, v_ts)
        if not current_meta: return
        
        virtual_path = current_meta['virtual_path']
        new_path = f"{virtual_path}.del_{delete_timestamp}"
        new_filename = f"{os.path.basename(virtual_path)}.del_{delete_timestamp}"
        
        query = '''UPDATE files 
                   SET is_active = 0, virtual_path = ?, filename = ?, v_ts = ? 
                   WHERE uuid = ? AND v_ts = ?'''
        params =  (new_path, new_filename, delete_timestamp, uuid, v_ts)
        self.cursor.execute(query, params)
        self.db.commit()

    
    def get_active_files(self):
        query = '''
            SELECT uuid, MAX(v_ts) as v_ts 
            FROM files 
            WHERE is_active = 1 
            GROUP BY uuid
        '''
        self.cursor.execute(query)
        
        return [(row['uuid'], row['v_ts']) for row in self.cursor.fetchall()]
    
    def restore_file(self, uuid: bytes, v_ts: int, timestamp_search: int): 
        current_meta = self.get_meta(uuid, v_ts)
        if not current_meta: return
        
        delete_path = current_meta['virtual_path']
        suffix = f".del_{timestamp_search}"
        
        if delete_path.endswith(suffix):
            base_virtual_path = delete_path[:-len(suffix)]
            safe_virtual_path = self.assign_name(base_virtual_path)
            safe_filename = os.path.basename(safe_virtual_path)
            
            new_v_ts = int(time.time())
            
            query = '''UPDATE files 
                       SET virtual_path = ?, filename = ?, is_active = 1, v_ts = ? 
                       WHERE uuid = ? AND v_ts = ?'''
            self.cursor.execute(query, (safe_virtual_path, safe_filename, new_v_ts, uuid, v_ts))
            self.db.commit()
        
    def get_meta(self, uuid: bytes, v_ts: int) -> dict:
        query = 'SELECT * from files where uuid = ? AND v_ts = ?'
        self.cursor.execute(query, (uuid, v_ts))
        row = self.cursor.fetchone()
        return dict(row) if row else None

    def get_complete_meta(self):
        query = 'SELECT * FROM files'
        self.cursor.execute(query)
        return [dict(row) for row in self.cursor.fetchall()]

    def close_connection(self):
        if hasattr(self, 'cursor'):
            self.cursor.close()
        if hasattr(self, 'db'):
            self.db.commit() 
            self.db.close()

    def purge_inactive_files(self):
        query = 'DELETE FROM files WHERE is_active = 0'
        self.cursor.execute(query)
        self.db.commit()

    def generate_sync_ledger(self) -> dict:
        self.cursor.execute("SELECT uuid, v_ts, is_active FROM files")
        ledger = {}
        for row in self.cursor.fetchall():
            action_state = "EDIT" if row['is_active'] else "DELETE"
            
            ledger[row['uuid']] = {
                "v_ts": row['v_ts'],
                "action": action_state
            }
        return ledger

    