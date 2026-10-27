import os
import sqlite3
import time

class TrustedDevicesDatabase:
    def __init__(self, storage_dir: str):
        self.db_path = os.path.join(storage_dir, "known_devices.db")

    def create_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(trusted_devices)")
            columns = [row[1] for row in cursor.fetchall()]
            if columns and ("vault_id" not in columns or "nickname" not in columns):
                cursor.execute("DROP TABLE trusted_devices")
            
            QUERY = '''CREATE TABLE IF NOT EXISTS trusted_devices (
            ml_dsa_hash BLOB NOT NULL,
            vault_id BLOB NOT NULL,
            device_name TEXT,
            device_type TEXT,
            nickname TEXT,
            ml_dsa_pub_key BLOB,
            added_timestamp REAL NOT NULL,
            last_seen REAL NOT NULL,
            is_paused INT,
            is_compromised INT DEFAULT 0,
            PRIMARY KEY (ml_dsa_hash, vault_id)
            )'''
            #device name = John Doe's Computer, Device_type = Windws/MacOS/ Linux Laptop, Desktop, PC, Iphone, Android
            cursor.execute(QUERY)
            conn.commit()

    
    def add_trusted_device(self, ml_dsa_hash: bytes, vault_id: bytes, device_name: str, device_type: str, ml_dsa_pub_key: bytes, nickname: str = None) -> bool:
        curr_time = time.time()
        nick = nickname if nickname else device_name
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY1 = '''SELECT last_seen FROM trusted_devices WHERE ml_dsa_hash = ? AND vault_id = ?'''
                cursor.execute(QUERY1, (ml_dsa_hash, vault_id))

                row = cursor.fetchone()
                preserved_last_seen = row[0] if row else 0
                QUERY2 = '''INSERT OR REPLACE INTO trusted_devices
                (ml_dsa_hash, vault_id, device_name, device_type, nickname, ml_dsa_pub_key, added_timestamp, last_seen, is_paused, is_compromised)
                VALUES (?,?,?,?,?,?,?,?,0,0)'''
                cursor.execute(QUERY2, (ml_dsa_hash, vault_id, device_name, device_type, nick, ml_dsa_pub_key, curr_time, preserved_last_seen))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"[-] Database Error (Add): {e}")
            return False
    
    def is_device_trusted(self, ml_dsa_hash: bytes, vault_id: bytes) -> dict | None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                QUERY = '''SELECT * FROM trusted_devices
                WHERE ml_dsa_hash = ? AND vault_id = ? AND ml_dsa_pub_key IS NOT NULL AND is_compromised = 0'''
                cursor.execute(QUERY, (ml_dsa_hash, vault_id))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                return None
        except sqlite3.Error as e:
            print(f"[-] Database Error (Read): {e}")
            return None
    
    def remove_peer(self, ml_dsa_hash: bytes, vault_id: bytes) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''Update trusted_devices
                SET ml_dsa_pub_key = NULL,
                    device_name = NULL,
                    device_type = NULL,
                    nickname = NULL,
                    is_paused = 0
                WHERE ml_dsa_hash = ? AND vault_id = ?'''
                
                cursor.execute(QUERY, (ml_dsa_hash, vault_id))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"[-] Database Error (Remove): {e}")
            return False
        


    def set_nickname(self, ml_dsa_hash: bytes, vault_id : bytes, nickname : str):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''UPDATE trusted_devices SET nickname = ?
                WHERE ml_dsa_hash = ? AND vault_id = ? AND ml_dsa_pub_key IS NOT NULL AND is_compromised = 0'''
                cursor.execute(QUERY, (nickname, ml_dsa_hash, vault_id))
                conn.commit()
        except sqlite3.Error as e:
            print(f"Database error : {e}")
            return 

    def set_pause_state(self, ml_dsa_hash : bytes, vault_id: bytes, is_paused : bool):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''UPDATE trusted_devices SET is_paused = ?
                WHERE ml_dsa_hash = ? AND vault_id = ? AND ml_dsa_pub_key IS NOT NULL AND is_compromised = 0'''
                bool_val = 0
                if is_paused:
                    bool_val = 1
                cursor.execute(QUERY, (bool_val, ml_dsa_hash, vault_id))
                conn.commit()
        except sqlite3.Error as e:
            print(f"Database error : {e}") 

    def update_last_seen(self, ml_dsa_hash : bytes, vault_id : bytes, last_seen_ts : int = None ):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                last_seen = last_seen_ts if last_seen_ts else int(time.time())
                UPDATE_QUERY = '''UPDATE trusted_devices SET last_seen = ? WHERE ml_dsa_hash = ? AND vault_id = ? AND ml_dsa_pub_key IS NOT NULL'''
                cursor.execute(UPDATE_QUERY, (last_seen, ml_dsa_hash, vault_id))
                conn.commit()
        except sqlite3.Error as e:
            print(f"[-] Database Error (Get Partner): {e}")
            return None
    
    def get_all_peers(self) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                QUERY = '''SELECT ml_dsa_hash, vault_id, device_name, nickname, device_type, ml_dsa_pub_key, is_paused, added_timestamp, last_seen 
                           FROM trusted_devices'''
                cursor.execute(QUERY)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[-] Database Error (Get All): {e}")
            return []

    def get_vault_peers(self, vault_id : bytes) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                QUERY = '''SELECT device_name, nickname, ml_dsa_hash, device_type, ml_dsa_pub_key, is_paused, added_timestamp, last_seen 
                           FROM trusted_devices
                           WHERE vault_id = ? AND ml_dsa_pub_key IS NOT NULL AND is_compromised = 0'''
                cursor.execute(QUERY, (vault_id,))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[-] Database Error (Get All): {e}")
            return []

    def mark_device_compromised(self, ml_dsa_hash: bytes) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''UPDATE trusted_devices SET is_compromised = 1 WHERE ml_dsa_hash = ?'''
                cursor.execute(QUERY, (ml_dsa_hash,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def check_if_compromised(self, ml_dsa_hash: bytes) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''SELECT is_compromised FROM trusted_devices WHERE ml_dsa_hash = ?'''
                cursor.execute(QUERY, (ml_dsa_hash,))
                rows = cursor.fetchall()
                # If ANY record for this device is marked compromised, return True
                return any(row[0] == 1 for row in rows)
        except sqlite3.Error:
            return False

    def get_last_seen(self, ml_dsa_hash: bytes, vault_id : bytes):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                QUERY = '''SELECT last_seen FROM trusted_devices WHERE ml_dsa_hash = ? AND vault_id = ?'''
                cursor.execute(QUERY, (ml_dsa_hash, vault_id))
                last_seen = cursor.fetchone()

                return last_seen
        except sqlite3.Error:
            return None
            