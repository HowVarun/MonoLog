import os
import time
import socket
import threading

import sys
from pathlib import Path

# Dynamically resolve and insert the project root directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.orchestrator import VaultManager
from modules.daemons import SyncWorker, TaSkewer
from modules.network import SecureNetworkTransport

MASTER_PASS = "Titanium123!"
WEAK_PASS = "123456"

def setup_test_vault(name: str):
    filepath = f"{name}.scaf"
    if os.path.exists(filepath):
        os.remove(filepath)
    if os.path.exists(filepath + ".sync.enc"):
        os.remove(filepath + ".sync.enc")
        
    vault = VaultManager(filepath)
    vault.create_new_vault(MASTER_PASS, WEAK_PASS)
    vault.unlock_hash(MASTER_PASS, WEAK_PASS)
    vault.boot_vault()
    
    vault.skewer = TaSkewer(vault) 
    return vault

def run_server(worker_b):
    """Vault B acts as the Host/Server."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 8000))
    server_sock.listen(1)
    
    print("[SERVER] Vault B listening on 127.0.0.1:8000...")
    client_sock, addr = server_sock.accept()
    print("[SERVER] Vault A connected!")
    
    transport = SecureNetworkTransport(sock=client_sock)
    
    # We strictly use the worker_b passed into this thread!
    worker_b.is_running = True
    worker_b._execute_sync_session(transport, peer_hash="mock_hash_B", is_client=False)
    
    server_sock.close()
    print("[SERVER] Sync Session Complete.")

def run_test():
    print("--- 1. Setting up Vaults ---")
    vault_a = setup_test_vault("Vault_A")
    vault_b = setup_test_vault("Vault_B")
    
    print("--- 2. Creating Dummy Data in Vault A ---")
    with open("dummy.txt", "w") as f:
        f.write("This is a highly classified test document for the SyncWorker.")
        
    vault_a.ingest_file("dummy.txt", "/documents/dummy.txt")
    
    print(f"Vault A Unsynced Payload: {vault_a.ledger.get_unsynced_payload()}")

    print("--- 3. Initializing Identities Sequentially ---")
    # Initialize and attach Skewers for both workers BEFORE threading
    worker_a = SyncWorker(vault_a)
    worker_a.skewer = vault_a.skewer
    
    worker_b = SyncWorker(vault_b)
    worker_b.skewer = vault_b.skewer
    
    print("--- 4. Starting Network Sync ---")
    # Pass the fully assembled worker_b directly to the thread
    t = threading.Thread(target=run_server, args=(worker_b,))
    t.start()
    
    time.sleep(1) # Let server boot
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", 8000))
    
    transport = SecureNetworkTransport(sock=client_sock)
    worker_a.is_running = True
    
    print("[CLIENT] Vault A initiating sync...")
    worker_a._execute_sync_session(transport, peer_hash="mock_hash_A", is_client=True)
    
    t.join()
    
    print("--- 5. Verification ---")
    time.sleep(0.5) # Let TaSkewer finish writing the DB
    
    db_b = vault_b.vaultdb.get_complete_meta()
    print(f"\nVault B Database State: {db_b}")
    
    if len(db_b) > 0 and db_b[0]['virtual_path'] == "/documents/dummy.txt":
        print("\n✅ SUCCESS: Network engine perfectly replicated the file into Vault B!")
    else:
        print("\n❌ FAILED: File did not appear in Vault B.")
        
    # Cleanup
    vault_a.lock_vault()
    vault_b.lock_vault()
    os.remove("dummy.txt")

if __name__ == "__main__":
    run_test()