import unittest
import os
import tempfile
import time

# Adjust these imports depending on how you split your folders!
from modules.crypto_core import MfaKdf, AesGcm 
from modules.vaultmap import VaultMap, VaultDatabase 

class TestPhase2_Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Runs ONCE before all tests. Sets up the Sample_files environment."""
        cls.sample_dir = os.path.join("modules", "Sample_files")
        os.makedirs(cls.sample_dir, exist_ok=True)
        
        # Create 3 dummy files just in case the folder is empty
        cls.files = ["test1.txt", "test2.pdf", "test3.mp4"]
        cls.real_paths = []
        for file in cls.files:
            path = os.path.join(cls.sample_dir, file)
            with open(path, "wb") as f:
                f.write(os.urandom(1024 * 5)) # 5KB of random data
            cls.real_paths.append(path)

    @classmethod
    def tearDownClass(cls):
        """Cleans up the sample files after all tests finish."""
        for path in cls.real_paths:
            if os.path.exists(path):
                os.remove(path)
        if os.path.exists(cls.sample_dir) and not os.listdir(cls.sample_dir):
            os.rmdir(cls.sample_dir)

    def setUp(self):
        """Runs before EACH test to reset the cryptography and temp files."""
        self.kdf = MfaKdf()
        self.key = self.kdf.derive("admin", "admin")
        self.engine = AesGcm(self.key)
        
        self.vault_file_fd, self.vault_file = tempfile.mkstemp()
        os.close(self.vault_file_fd)
        
        self.output_file_fd, self.output_file = tempfile.mkstemp()
        os.close(self.output_file_fd)

    def tearDown(self):
        """Cleans up the encrypted vaults after EACH test."""
        if os.path.exists(self.vault_file): os.remove(self.vault_file)
        if os.path.exists(self.output_file): os.remove(self.output_file)

    # --- TEST 1: The Hashmap Injection Attack ---
    def test_hashmap_injection(self):
        v_map = VaultMap()
        virtual_path = "/docs/secret.txt"
        
        # 1. Encrypt and map
        meta = self.engine.encrypt_file(self.real_paths[0], self.vault_file)
        v_map.add_file(virtual_path, meta, 5120)
        
        # 2. THE ATTACK: Maliciously flip a byte in the IV stored in the map
        corrupted_meta = v_map.get_meta(virtual_path)["meta_data"]
        original_iv = corrupted_meta[0]["IV"]
        corrupted_meta[0]["IV"] = b'\x00' + original_iv[1:] # Altering the first byte
        
        # 3. Attempt decryption using the poisoned hashmap
        dec_engine = AesGcm(self.key)
        success = dec_engine.decrypt_file(corrupted_meta, self.vault_file, self.output_file)
        
        # MUST fail cleanly without crashing the app
        self.assertFalse(success, "CRITICAL: Engine accepted a tampered Hashmap IV!")

    # --- TEST 2: Serialization Survival & Decryption ---
    def test_serialization_decryption(self):
        v_map = VaultMap()
        virtual_path = "/docs/survivor.pdf"
        
        # 1. Encrypt and map
        meta = self.engine.encrypt_file(self.real_paths[1], self.vault_file)
        v_map.add_file(virtual_path, meta, 5120)
        
        # 2. Pack to binary and destroy the original map
        packed_bytes = v_map.pack_map()
        del v_map 
        
        # 3. Unpack to a brand new map
        recovered_map = VaultMap(packed_bytes)
        recovered_meta = recovered_map.get_meta(virtual_path)["meta_data"]
        
        # 4. Decrypt using the recovered data
        dec_engine = AesGcm(self.key)
        success = dec_engine.decrypt_file(recovered_meta, self.vault_file, self.output_file)
        
        self.assertTrue(success, "MsgPack corrupted the chunk data during serialization!")

    # --- TEST 3: SQLite Routing and SQL Injection ---
    def test_sqlite_injection_and_routing(self):
        v_map = VaultMap()
        db = VaultDatabase()
        
        # 1. Add multiple files to the map and sync to DB
        v_map.add_file("/media/video1.mp4", [], 1000)
        v_map.add_file("/media/video2.mp4", [], 2000)
        db.db_map_sync(v_map.map)
        
        # 2. Routing Test: Use the DB to get the filename
        results = db.get_files_in_folder("/media/")
        self.assertEqual(len(results), 2)
        ui_filename = results[0][0] # Should be 'video1.mp4'
        self.assertEqual(ui_filename, "video1.mp4")
        
        # 3. THE ATTACK: SQL Injection attempt on the folder path
        malicious_input = "'; DROP TABLE files; --"
        results_hack = db.get_files_in_folder(malicious_input)
        
        # 4. Verification
        # If parameterized queries (?) work, it treats it as a literal folder search and returns nothing.
        # If it failed, the table would be dropped and the next query would crash.
        self.assertEqual(len(results_hack), 0, "SQL Injection returned data!")
        
        # Prove table still exists
        safe_check = db.get_files_in_folder("/media/")
        self.assertEqual(len(safe_check), 2, "CRITICAL: SQL Injection dropped the table!")

    # --- TEST 4: Ghost File Deletion (Sync Logic) ---
    def test_ghost_file_deletion(self):
        v_map = VaultMap()
        db = VaultDatabase()
        
        virtual_path = "/docs/financials.pdf"
        dummy_chunks = [{"IV": b"fake", "Start": 0, "End": 10}]
        
        v_map.add_file(virtual_path, dummy_chunks, 100)
        db.db_map_sync(v_map.map)
        
        # 1. Delete the file
        v_map.set_active_status(virtual_path, False)
        
        # Since your DB doesn't have a direct 'update' method from the map yet,
        # we sync it again to simulate a vault reboot.
        db.db_map_sync(v_map.map) 
        
        # 2. Database should hide it (is_active = 0)
        ui_results = db.get_files_in_folder("/docs/")
        self.assertEqual(len(ui_results), 0, "UI Database failed to hide deleted file!")
        
        # 3. Hashmap MUST keep it (Ghost Recovery)
        crypto_meta = v_map.get_meta(virtual_path)
        self.assertIsNotNone(crypto_meta, "Map deleted the file! Ghost recovery impossible.")
        self.assertFalse(crypto_meta["is_active"])

    # --- TEST 5: File Version Overwrite (INSERT OR REPLACE) ---
    def test_file_version_overwrite(self):
        v_map = VaultMap()
        db = VaultDatabase()
        virtual_path = "/docs/resume.pdf"
        
        # Upload version 1
        v_map.add_file(virtual_path, [], 100)
        db.db_map_sync(v_map.map)
        
        # Upload version 2 (Same path, bigger size)
        v_map.add_file(virtual_path, [], 500)
        db.db_map_sync(v_map.map)
        
        # Query the DB
        # If 'INSERT OR REPLACE' failed, there will be 2 files here.
        # If it worked, there will be 1 file, and the size will be 500.
        db.cursor.execute("SELECT size_bytes FROM files WHERE full_path = ?", (virtual_path,))
        rows = db.cursor.fetchall()
        
        self.assertEqual(len(rows), 1, "Database created a duplicate row instead of updating!")
        self.assertEqual(rows[0][0], 500, "Database failed to update the file size!")

if __name__ == '__main__':
    unittest.main(verbosity=2)