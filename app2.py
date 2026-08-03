import os
import time
import struct
import traceback
from modules.orchestrator import VaultManager
from modules.orchestrator import VaultDynamicManager

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ==========================================
# The Virtual Directory Explorers
# ==========================================
def explore_vault(manager):
    """Provides a numbered, interactive directory tree for selecting files."""
    current_dir = "/"
    
    while True:
        clear_screen()
        active_files = manager.vaultdb.get_active_files()
        
        folders = set()
        files = []
        
        for uuid, v_ts in active_files:
            meta = manager.vaultdb.get_meta(uuid, v_ts)
            path = meta['virtual_path']
            
            if path.startswith(current_dir):
                remainder = path[len(current_dir):]
                if "/" in remainder:
                    folder_name = remainder.split("/")[0]
                    folders.add(folder_name)
                elif remainder:
                    files.append((remainder, uuid, v_ts))
                    
        folders = sorted(list(folders))
        files = sorted(files, key=lambda x: x[0])
        
        print("\n" + "="*50)
        print(f" 📂 SELECT FILE: {current_dir}")
        print("="*50)
        print("0. [.. Go Back / Cancel]")
        
        item_map = {}
        index = 1
        
        for f in folders:
            print(f"{index}. 📁 {f}/")
            item_map[str(index)] = {"type": "dir", "name": f}
            index += 1
            
        for f_name, uuid, v_ts in files:
            print(f"{index}. 📄 {f_name}")
            item_map[str(index)] = {"type": "file", "name": f_name, "uuid": uuid, "v_ts": v_ts}
            index += 1
            
        if not folders and not files:
            print("   (Empty Directory)")
            
        choice = input("\nSelect a number: ")
        
        if choice == "0":
            if current_dir == "/":
                return None
            else:
                parts = current_dir.strip("/").split("/")
                parts.pop()
                current_dir = "/" + "/".join(parts) + "/" if parts else "/"
            continue
            
        if choice in item_map:
            selected = item_map[choice]
            if selected["type"] == "dir":
                current_dir += selected["name"] + "/"
            else:
                return selected["uuid"], selected["v_ts"]

def pick_directory(manager):
    """Interactive explorer for choosing where to save a new file."""
    current_dir = "/"
    
    while True:
        clear_screen()
        active_files = manager.vaultdb.get_active_files()
        
        folders = set()
        for uuid, v_ts in active_files:
            meta = manager.vaultdb.get_meta(uuid, v_ts)
            path = meta['virtual_path']
            
            if path.startswith(current_dir):
                remainder = path[len(current_dir):]
                if "/" in remainder:
                    folders.add(remainder.split("/")[0])
                    
        folders = sorted(list(folders))
        
        print("\n" + "="*40)
        print(f" 🎯 CHOOSE DESTINATION: {current_dir}")
        print("="*40)
        print("0. [.. Go Back / Cancel]")
        print("1. [✓ SAVE FILE IN THIS FOLDER]")
        print("2. [+ Create New Folder Here]")
        print("-" * 40)
        
        item_map = {}
        index = 3
        
        for f in folders:
            print(f"{index}. 📁 {f}/")
            item_map[str(index)] = f
            index += 1
            
        choice = input("\nSelect a number: ")
        
        if choice == "0":
            if current_dir == "/":
                return None
            else:
                parts = current_dir.strip("/").split("/")
                parts.pop()
                current_dir = "/" + "/".join(parts) + "/" if parts else "/"
            continue
        elif choice == "1":
            return current_dir
        elif choice == "2":
            new_folder = input("\nEnter new folder name: ").strip("/")
            if new_folder:
                current_dir += new_folder + "/"
        elif choice in item_map:
            current_dir += item_map[choice] + "/"


# ==========================================
# Automated Security Test Engine
# ==========================================
def run_security_suite(vaults_dir):
    clear_screen()
    print("\n" + "="*50)
    print(" 🛡️  INITIATING SECURITY & VULNERABILITY TESTS")
    print("="*50)
    
    # Generate a unique timestamped file to avoid OS ghost locks
    test_vault_path = os.path.join(vaults_dir, f"SEC_TEST_SANDBOX_{int(time.time())}.scaf")
    mp, wp = "TestMaster123!", "9999"
    passed_tests = 0
    total_tests = 5

    # TEST 1: Creation and RAM Zeroization
    print("\n[Test 1/5] RAM Zeroization & Memory Safety...")
    try:
        test_manager = VaultManager(test_vault_path)
        test_manager.create_new_vault(mp, wp)
        
        active_dek = getattr(test_manager, 'dek', None)
        if active_dek is None or active_dek == b'\x00' * 32:
            print("  [X] FAILED: DEK failed to generate/load in RAM.")
        else:
            test_manager.lock_vault()
            wiped_dek = getattr(test_manager, 'dek', None)
            if wiped_dek and wiped_dek != b'\x00' * 32:
                print(f"  [X] FAILED (MEMORY LEAK): DEK not zeroed! Found: {wiped_dek.hex()}")
            else:
                print("  [✓] PASSED: DEK successfully zeroed/removed from memory space upon lock.")
                passed_tests += 1
    except Exception as e:
        print(f"  [X] ERROR IN TEST 1: {type(e).__name__} - {e}")
        for line in traceback.format_exc().splitlines()[-3:]:
            print(f"      {line}")

    # TEST 2: OS-Level Process Concurrency
    print("\n[Test 2/5] OS Kernel Concurrency Lock (Portalocker)...")
    try:
        if not os.path.exists(test_vault_path):
            print("  [!] SKIPPED: Test vault does not exist (Test 1 likely failed).")
        else:
            # Instantiate a fresh manager to ensure a clean slate
            manager_t2 = VaultManager(test_vault_path)
            manager_t2.unlock_hash(mp, wp)
            manager_t2.boot_vault()
            
            try:
                rogue_manager = VaultManager(test_vault_path)
                rogue_manager.unlock_hash(mp, wp)
                rogue_manager.boot_vault()
                print("  [X] FAILED: Rogue manager successfully bypassed file locks!")
            except Exception as rogue_e:
                if "Resource temporarily unavailable" in str(rogue_e) or "Permission denied" in str(rogue_e) or "locked" in str(rogue_e).lower():
                    print("  [✓] PASSED: Kernel rejected concurrent access request.")
                    passed_tests += 1
                else:
                    print(f"  [!] UNEXPECTED BEHAVIOR: {type(rogue_e).__name__} - {rogue_e}")
            finally:
                manager_t2.lock_vault()
    except Exception as e:
        print(f"  [X] ERROR IN TEST 2: {type(e).__name__} - {e}")
        for line in traceback.format_exc().splitlines()[-3:]:
            print(f"      {line}")

    # TEST 3: Cryptographic Header Tampering
    print("\n[Test 3/5] Header Tamper Resistance...")
    try:
        if not os.path.exists(test_vault_path):
             print("  [!] SKIPPED: Test vault does not exist.")
        else:
            with open(test_vault_path, 'r+b') as f:
                f.seek(0)
                f.write(b"FAIL")
                
            try:
                tamper_manager = VaultManager(test_vault_path)
                tamper_manager.unlock_hash(mp, wp)
                tamper_manager.boot_vault()
                print("  [X] FAILED: Vault booted despite corrupted magic number!")
            except Exception as header_e:
                print("  [✓] PASSED: VaultIO rejected malformed header state.")
                passed_tests += 1
            finally:
                with open(test_vault_path, 'r+b') as f:
                    f.seek(0)
                    f.write(b"SCAF")
    except Exception as e:
        print(f"  [X] ERROR IN TEST 3: {type(e).__name__} - {e}")
        for line in traceback.format_exc().splitlines()[-3:]:
            print(f"      {line}")

    # TEST 4: KDF Brute Force Rejection
    print("\n[Test 4/5] Authentication Rejection (Invalid Keys)...")
    try:
        if not os.path.exists(test_vault_path):
             print("  [!] SKIPPED: Test vault does not exist.")
        else:
            try:
                brute_manager = VaultManager(test_vault_path)
                brute_manager.unlock_hash("WrongMaster!", "0000")
                print("  [X] FAILED: Vault accepted invalid credentials!")
            except Exception as kdf_e:
                print("  [✓] PASSED: KDF strictly denied access. Key derivation failed safely.")
                passed_tests += 1
    except Exception as e:
        print(f"  [X] ERROR IN TEST 4: {type(e).__name__} - {e}")
        for line in traceback.format_exc().splitlines()[-3:]:
            print(f"      {line}")

    # TEST 5: Sandbox Cleanup Validation
    print("\n[Test 5/5] Secure Test Sandbox Deletion...")
    try:
        if os.path.exists(test_vault_path):
            os.remove(test_vault_path)
        
        if not os.path.exists(test_vault_path):
            print("  [✓] PASSED: Test environment unlinked from OS filesystem.")
            passed_tests += 1
        else:
            print("  [X] FAILED: Test environment was not deleted.")
    except Exception as e:
        print(f"  [X] ERROR IN TEST 5: {type(e).__name__} - {e}")
        for line in traceback.format_exc().splitlines()[-3:]:
            print(f"      {line}")
        
    # Final Failsafe Cleanup outside of test evaluation
    if os.path.exists(test_vault_path):
        try: os.remove(test_vault_path)
        except: pass

    print("\n" + "="*50)
    print(f" TEST RESULTS: {passed_tests} / {total_tests} Tests Passed.")
    print("="*50)
    input("\nPress Enter to return to menu.")

# ==========================================
# Main Menus
# ==========================================
def main_menu():
    clear_screen()
    print("\n" + "="*40)
    print(" 🛡️  SECURE VAULT V2 - TEST INTERFACE  ")
    print("="*40)
    print("1. Create New Vault")
    print("2. Unlock Existing Vault")
    print("3. Exit")
    return input("Select an option: ")

def vault_menu(vault_path):
    clear_screen()
    print("\n" + "="*40)
    print(f" 🔓 ACTIVE VAULT: {os.path.basename(vault_path)}")
    print("="*40)
    print("1. Add a File (Ingest)")
    print("2. Preview / Launch a File")
    print("3. Delete a File")
    print("4. Rename a File")
    print("5. View Network Sync Ledger (Debug)")
    print("6. Run Defragmentation (Vacuum)")
    print("7. Change Vault Password")
    print("8. Lock & Close Vault")
    print("9. Run Automated Security Diagnostics")
    return input("Select an option: ")

def check_mem_state(manager):
    """Helper to safely display bytearray status without crashing."""
    if not manager:
        return "WIPED (None)"
    
    dek = getattr(manager, 'dek', None)
    
    if not dek:
        return "WIPED (None)"
    if dek == b'\x00' * 32:
        return "WIPED (Zeroed)"
    return dek.hex()[:16] + "..."

def run_cli():
    manager = None
    active_vault_path = ""
    vaults_dir = "Vaults"
    
    os.makedirs(vaults_dir, exist_ok=True)

    while True:
        if not manager:
            choice = main_menu()
            
            if choice == '1':
                path = input("\nEnter new vault filename (e.g., test.scaf): ")
                if not path.endswith('.scaf'):
                    path += '.scaf'
                active_vault_path = os.path.join(vaults_dir, path)
                
                mp = input("Enter Master Password: ")
                wp = input("Enter Weak PIN: ")
                
                manager = VaultManager(active_vault_path)
                try:
                    manager.create_new_vault(mp, wp)
                    input("\n[+] Vault created! Press Enter to continue.")
                except Exception as e:
                    print(f"\n[!] Error: {e}")
                    manager = None
                    time.sleep(2)

            elif choice == '2':
                existing_vaults = [f for f in os.listdir(vaults_dir) if f.endswith('.scaf')]
                
                if not existing_vaults:
                    input(f"\n[!] No .scaf vaults found in '{vaults_dir}'. Press Enter to return.")
                    continue
                
                print("\n[*] Available Vaults:")
                for idx, v_name in enumerate(existing_vaults, 1):
                    print(f"  {idx}. {v_name}")
                print("  0. Cancel")
                
                v_choice = input("\nSelect a vault number: ")
                if v_choice == '0' or not v_choice.isdigit() or int(v_choice) < 1 or int(v_choice) > len(existing_vaults):
                    continue
                    
                selected_vault = existing_vaults[int(v_choice) - 1]
                active_vault_path = os.path.join(vaults_dir, selected_vault)
                    
                mp = input("Enter Master Password: ")
                wp = input("Enter Weak PIN: ")
                
                manager = VaultManager(active_vault_path)
                try:
                    manager.unlock_hash(mp, wp)
                    manager.boot_vault()
                    input("\n[+] Vault unlocked! Press Enter to continue.")
                except Exception as e:
                    print(f"\n[!] Error unlocking vault: {e}")
                    manager = None
                    time.sleep(2)

            elif choice == '3':
                break

        else:
            choice = vault_menu(active_vault_path)
            
            if choice == '1':
                source = input("\nEnter full path of local file to upload: ")
                if not os.path.exists(source):
                    input("[!] Local file not found. Press Enter.")
                    continue
                
                target_dir = pick_directory(manager)
                if target_dir:
                    default_name = os.path.basename(source)
                    v_name = input(f"\nEnter filename for vault (Leave blank to use '{default_name}'): ")
                    if not v_name.strip():
                        v_name = default_name
                        
                    v_path = target_dir + v_name
                    try:
                        manager.ingest_file(source, v_path)
                        input(f"\n[+] Added to vault as {v_path}. Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '2':
                selection = explore_vault(manager)
                if selection:
                    file_uuid, v_ts = selection
                    meta = manager.vaultdb.get_meta(file_uuid, v_ts)
                    print(f"\n[*] Decrypting and launching [{meta['virtual_path']}]...")
                    try:
                        manager.preview_file(file_uuid, v_ts)
                        input(f"\n[+] Ghost file launched! Press Enter to continue.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '3':
                selection = explore_vault(manager)
                if selection:
                    file_uuid, v_ts = selection
                    meta = manager.vaultdb.get_meta(file_uuid, v_ts)
                    
                    confirm = input(f"\nAre you sure you want to delete [{meta['virtual_path']}]? (y/n): ")
                    if confirm.lower() == 'y':
                        try:
                            manager.delete_file(file_uuid, v_ts)
                            input(f"\n[-] {meta['virtual_path']} marked for deletion. Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            elif choice == '4':
                selection = explore_vault(manager)
                if selection:
                    file_uuid, v_ts = selection
                    meta = manager.vaultdb.get_meta(file_uuid, v_ts)
                    
                    print(f"\nCurrent Path: {meta['virtual_path']}")
                    new_path = input("Enter new path (e.g. /Photos/vacation.jpg): ")
                    if new_path:
                        if not new_path.startswith('/'):
                            new_path = '/' + new_path
                        try:
                            manager.rename_file(file_uuid, v_ts, new_path)
                            input(f"\n[+] Renamed successfully! Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            elif choice == '5':
                clear_screen()
                print("\n" + "="*40)
                print(" 📜 CURRENT SYNC LEDGER STATE")
                print("="*40)
                try:
                    ledger_data = manager.ledger.get_ledger()
                    if not ledger_data:
                        print("Ledger is currently empty (Fully synced or new).")
                    else:
                        for idx, event in enumerate(ledger_data, 1):
                            uuid, v_ts, action = event
                            meta = manager.vaultdb.get_meta(uuid, v_ts)
                            path = meta['virtual_path'] if meta else "UNKNOWN (Deleted?)"
                            print(f"{idx}. [{action}] {uuid.hex()[:8]}... | TS: {v_ts} | Path: {path}")
                except Exception as e:
                    print(f"[!] Could not read ledger: {e}")
                input("\nPress Enter to return.")

            elif choice == '6':
                dyn_manager = VaultDynamicManager(manager)
                print("\n" + "="*40)
                print(" 🧹 RUNNING DEFRAGMENTATION")
                print("="*40)
                
                print(f"[*] Pre-Defrag DEK Memory  : {check_mem_state(manager)}")
                
                try:
                    dyn_manager.run_vacuum()
                    print(f"[*] Post-Defrag DEK Memory : {check_mem_state(manager)}")
                    input("\n[+] Defragmentation complete! Vault remains open. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error during defragmentation: {e}. Press Enter.")

            elif choice == '7':
                dyn_manager = VaultDynamicManager(manager)
                print("\n" + "="*40)
                print(" 🔑 CHANGING VAULT CREDENTIALS")
                print("="*40)
                
                print(f"[*] Current DEK in Memory  : {check_mem_state(manager)}\n")
                
                old_mp = input("Enter Current Master Password: ")
                old_wp = input("Enter Current Weak PIN: ")
                new_mp = input("Enter NEW Master Password: ")
                new_wp = input("Enter NEW Weak PIN: ")
                
                try:
                    dyn_manager.change_vault_password(old_mp, old_wp, new_mp, new_wp)
                    print(f"[*] Post-Change DEK Memory : {check_mem_state(manager)}")
                    
                    input("\n[+] Password changed successfully! Vault has been LOCKED for security. Press Enter.")
                    manager = None
                    active_vault_path = ""
                except Exception as e:
                    input(f"\n[!] Error changing credentials: {e}. Press Enter.")

            elif choice == '8':
                manager.lock_vault()
                input("\n[*] Vault locked. RAM shredded. Ledger encrypted. Press Enter.")
                manager = None
                active_vault_path = ""
                
            elif choice == '9':
                run_security_suite(vaults_dir)

if __name__ == "__main__":
    run_cli()