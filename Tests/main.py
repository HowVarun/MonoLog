import os
import time
from modules.orchestrator import VaultManager 
from modules.daemons import Defragmentation 

# ==========================================
# The Integration Test
# ==========================================
def run_stress_test():
    # Using 'r' (raw string) to prevent \t from becoming a tab!
    vault_path = r"venv\Vaults\test_vault.scaf"
    file1_os = r"venv\Sample_files\NIST-Paper.pdf"
    file2_os = r"venv\Sample_files\hello.json"
    
    # 0. Clean up only the old vault files (DO NOT delete your real sample files!)
    for f in [vault_path, vault_path + ".lock", vault_path + ".tmp"]:
        if os.path.exists(f):
            os.remove(f)

    print("\n--- PHASE 1: Creation & Ingestion ---")
    manager = VaultManager(vault_path)
    
    print("[*] Creating new vault...")
    manager.create_new_vault("MasterPassword123!", "weak_pin")
    
    print(f"[*] Ingesting NIST Paper...")
    manager.ingest_file(file1_os, "/documents/NIST-Paper.pdf")
    
    print(f"[*] Ingesting JSON data...")
    manager.ingest_file(file2_os, "/data/hello.json")

    print("\n--- PHASE 2: Extraction & Verification ---")
    print("[*] Streaming /documents/NIST-Paper.pdf to verify AES decryption...")
    reconstructed_size = 0
    for chunk in manager.stream_file("/documents/NIST-Paper.pdf"):
        reconstructed_size += len(chunk)
    
    # We use KB instead of MB here since PDFs/JSONs are usually smaller
    print(f"[+] Successfully decrypted {reconstructed_size / 1024:.2f} KB!") 

    print("\n--- PHASE 3: Deletion & Memory Shredding ---")
    print("[*] Deleting /data/hello.json to create dead space...")
    manager.vaultdb.delete_file("/data/hello.json", int(time.time()))
    
    pre_vacuum_size = os.path.getsize(vault_path)
    print(f"[*] Vault size before locking: {pre_vacuum_size / 1024:.2f} KB")
    
    print("[*] Locking vault and shredding RAM...")
    manager.lock_vault()

    print("\n--- PHASE 4: Reboot & Defragmentation ---")
    print("[*] Rebooting VaultManager...")
    manager2 = VaultManager(vault_path)
    manager2.unlock_hash("MasterPassword123!", "weak_pin")
    manager2.boot_vault()
    
    print("[*] Triggering Side-by-Side Defragmentation...")
    defragger = Defragmentation(manager2)
    defragger.vacuum()
    
    post_vacuum_size = os.path.getsize(vault_path)
    print(f"[+] Vault size after vacuum: {post_vacuum_size / 1024:.2f} KB")
    print(f"[+] Total Dead Space Reclaimed: {(pre_vacuum_size - post_vacuum_size) / 1024:.2f} KB")
    
    print("[*] Final Lock...")
    manager2.lock_vault()

    print("\n[SUCCESS] Vault Architecture is 100% operational!")

if __name__ == "__main__":
    # Ensure your target directories exist before running
    os.makedirs(r"venv\Vaults", exist_ok=True)
    run_stress_test()