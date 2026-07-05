import sqlite3
import os

class VaultDatabase:
    def __init__(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.cursor = self.db.cursor()
        self._create_schema()
        
    def db_map_sync(self, vault_map_dict: dict):
        info = []
        for file_id, meta_data in vault_map_dict.items():
            virtual_path = meta_data.get("virtual_path")
            file_name = os.path.basename(virtual_path)
            parent_folder = os.path.dirname(virtual_path) + '/'
            info.append((
                file_id, 
                file_name, 
                parent_folder, 
                virtual_path, 
                meta_data.get("size_bytes"), 
                meta_data.get("created_at"), 
                meta_data.get("is_active")
            ))
            
        query = '''
            INSERT OR REPLACE INTO files 
            (file_id, filename, parent_folder, virtual_path, size_bytes, created_at, is_active) 
            VALUES (?,?,?,?,?,?,?)
        '''
        
        self.cursor.executemany(query, info)
        self.db.commit()

    def _create_schema(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id BLOB PRIMARY KEY,
                filename TEXT NOT NULL,
                parent_folder TEXT NOT NULL,
                virtual_path TEXT NOT NULL,
                size_bytes INTEGER,
                created_at INTEGER,
                is_active BOOLEAN
            )
        ''')
        
        self.cursor.execute('CREATE INDEX idx_folder ON files(parent_folder)')
        self.cursor.execute('CREATE INDEX idx_path ON files(virtual_path)')
        self.db.commit()
    
    def inmo_file(self, file_id: bytes, virtual_path: str, meta_data: dict):
        '''Insert or Modify file metadata'''
        file_name = os.path.basename(virtual_path)
        relative_dir = os.path.dirname(virtual_path) + '/'
        params = (file_id, file_name, relative_dir, virtual_path, meta_data.get("size_bytes"), meta_data.get("created_at"), meta_data.get("is_active"))

        query = 'INSERT OR REPLACE INTO files (file_id, filename, parent_folder, virtual_path, size_bytes, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)'
        self.cursor.execute(query, params)
        self.db.commit()

    def get_files_in_folder(self, folder_path: str):
        if not folder_path.endswith('/'):
            folder_path += '/'
        query = 'SELECT file_id, filename, size_bytes, created_at FROM files WHERE parent_folder = ? AND is_active = 1'
        self.cursor.execute(query, (folder_path,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def delete_file(self, file_id: bytes, timestamp: int):
        # We fetch the current path first so we can append the .del_ marker
        current_meta = self.get_meta(file_id)
        if not current_meta: return
        
        virtual_path = current_meta['virtual_path']
        new_path = f"{virtual_path}.del_{timestamp}"
        new_filename = f"{os.path.basename(virtual_path)}.del_{timestamp}"
        
        query = '''UPDATE files 
                   SET is_active = 0, virtual_path = ?, filename = ? 
                   WHERE file_id = ?'''
        params =  (new_path, new_filename, file_id)
        self.cursor.execute(query, params)
        self.db.commit()
    
    def get_active_files(self):
        query = 'SELECT file_id FROM files WHERE is_active = 1'
        self.cursor.execute(query)
        return [row['file_id'] for row in self.cursor.fetchall()]
    
    def restore_file(self, file_id: bytes, timestamp_search : int, timestamp_set : int): 
        current_meta = self.get_meta(file_id)
        if not current_meta: return
        
        delete_path = current_meta['virtual_path']
        virtual_path = delete_path.replace(f".del_{timestamp_search}", "")
        archive_path = f"{virtual_path}.del_{timestamp_set}"
        
        query = 'UPDATE files SET virtual_path = ? WHERE file_id = ?'
        # To strictly replicate your old logic, you would handle the conflict checking here
        self.cursor.execute(query, (virtual_path, file_id))
        self.db.commit()
        
    def get_meta(self, file_id : bytes) -> dict:
        query = 'SELECT * from files where file_id = ?'
        self.cursor.execute(query, (file_id,))
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