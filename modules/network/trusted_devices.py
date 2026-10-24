import os
import sqlite3
import time

class TrustedDevicesDatabase:
    def __init__(self, storage_dir: str):
        self.db_path = os.path.join(storage_dir, "known_devices.db")

    def create_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            QUERY = '''CREATE TABLE IF NOT EXISTS trusted_devices (
            ml_dsa_hash BLOB NOT NULL,
            vault_id BLOB NOT NULL,
            device_name TEXT NOT NULL,
            device_type TEXT NOT NULL,
            ml_dsa_pub_key BLOB NOT NULL,
            added_timestamp REAL NOT NULL,
            last_seen REAL NOT NULL,
            PRIMARY KEY (ml_dsa_hash, vault_id)
            )'''
            #device name = John Doe's Computer, Device_type = Windws/MacOS/ Linux Laptop, Desktop, PC, Iphone, Android
            cursor.execute(QUERY)
            conn.commit()

    
    def add_trusted_device(self, ml_dsa_hash: str, vault_id: bytes ,device_name: str, device_type: str, ml_dsa_pub_key: bytes) -> bool:
        curr_time = time.time()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''INSERT OR REPLACE INTO trusted_devices
                (ml_dsa_hash, vault_id,device_name, device_type, ml_dsa_pub_key, added_timestamp, last_seen) 
                VALUES (?,?,?,?,?,?,?)
                '''
                cursor.execute(QUERY, (ml_dsa_hash, vault_id, device_name, device_type, ml_dsa_pub_key, curr_time, curr_time))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"[-] Database Error (Add): {e}")
            return False
    
    def is_device_trusted(self, ml_dsa_hash: str, vault_id: bytes) -> dict | None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                QUERY = '''SELECT * FROM trusted_devices
                WHERE ml_dsa_hash = ? AND vault_id = ?'''
                cursor.execute(QUERY, (ml_dsa_hash, vault_id))
                row = cursor.fetchone()
                
                if row:
                    UPDATE_QUERY = '''UPDATE trusted_devices SET last_seen = ? WHERE ml_dsa_hash = ? AND vault_id = ?'''
                    cursor.execute(UPDATE_QUERY, (time.time(), ml_dsa_hash, vault_id))
                    conn.commit()
                    return dict(row)
                return None
        except sqlite3.Error as e:
            print(f"[-] Database Error (Read): {e}")
            return None
    
    def remove_peer(self, ml_dsa_hash: str, vault_id: bytes) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''DELETE FROM trusted_devices WHERE ml_dsa_hash = ? AND vault_id = ?'''
                cursor.execute(QUERY, (ml_dsa_hash, vault_id))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"[-] Database Error (Remove): {e}")
            return False
        
    def get_all_peers(self) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                QUERY = '''SELECT ml_dsa_hash, vault_id, device_name, device_type, ml_dsa_pub_key, added_timestamp, last_seen FROM trusted_devices'''
                cursor.execute(QUERY)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[-] Database Error (Get All): {e}")
            return []

    def get_vault_partner(self, vault_id: bytes) -> dict | None:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    QUERY = '''SELECT * FROM trusted_devices
                    WHERE vault_id = ?'''
                    cursor.execute(QUERY,(vault_id,))
                    row = cursor.fetchone()
                    return dict(row) if row else None
            except sqlite3.Error as e:
                print(f"[-] Database Error (Get Partner): {e}")
                return None