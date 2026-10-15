import os
import time
import struct
import traceback
from modules.orchestrator import VaultManager
from modules.orchestrator import VaultDynamicManager
from modules.daemons import SyncWorker, TaSkewer 
from modules.crypto_core import hashing

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ==========================================
# The Virtual Directory Explorers
# ==========================================
def explore_vault(manager, include_deleted=False):
    current_dir = "/"
    
    while True:
        clear_screen()
        
        if include_deleted:
            active_files = []
            for row in manager.vaultdb.get_complete_meta():
                if not row['is_active']: 
                    active_files.append((row['uuid'], row['v_ts']))
        else:
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
        mode = "DELETED ARCHIVE" if include_deleted else "ACTIVE FILES"
        print(f" 📂 SELECT FILE ({mode}): {current_dir}")
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
            if current_dir == "/": return None
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
            if current_dir == "/": return None
            else:
                parts = current_dir.strip("/").split("/")
                parts.pop()
                current_dir = "/" + "/".join(parts) + "/" if parts else "/"
            continue
        elif choice == "1":
            return current_dir
        elif choice == "2":
            new_folder = input("\nEnter new folder name: ").strip("/")
            if new_folder: current_dir += new_folder + "/"
        elif choice in item_map:
            current_dir += item_map[choice] + "/"

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
    print("5. Restore/Reingest a Deleted File")
    print("6. View Network Sync Ledger")
    print("7. Run Defragmentation (Vacuum)")
    print("8. Rotate Master Encryption Key")
    print("9. Change Vault Password")
    print("10. Lock & Close Vault")
    print("11. Network Sync & Pairing")
    return input("Select an option: ")

def check_mem_state(manager):
    if not manager: return "WIPED (None)"
    dek = getattr(manager, 'dek', None)
    if not dek: return "WIPED (None)"
    if dek == b'\x00' * 32: return "WIPED (Zeroed)"
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
                if not path.endswith('.scaf'): path += '.scaf'
                active_vault_path = os.path.join(vaults_dir, path)
                mp, wp = input("Enter Master Password: "), input("Enter Weak PIN: ")
                
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
                    input(f"\n[!] No .scaf vaults found in '{vaults_dir}'. Press Enter.")
                    continue
                
                print("\n[*] Available Vaults:")
                for idx, v_name in enumerate(existing_vaults, 1): print(f"  {idx}. {v_name}")
                print("  0. Cancel")
                
                v_choice = input("\nSelect a vault number: ")
                if v_choice == '0' or not v_choice.isdigit() or int(v_choice) < 1 or int(v_choice) > len(existing_vaults):
                    continue
                    
                active_vault_path = os.path.join(vaults_dir, existing_vaults[int(v_choice) - 1])
                mp, wp = input("Enter Master Password: "), input("Enter Weak PIN: ")
                
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
                    if not v_name.strip(): v_name = default_name
                        
                    v_path = target_dir + v_name
                    try:
                        manager.ingest_file(source, v_path)
                        input(f"\n[+] Added to vault as {v_path}. Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}\n{traceback.format_exc()}\nPress Enter.")
                        manager = None # Crash failsafe

            elif choice == '2':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    try:
                        manager.preview_file(uuid, v_ts)
                        input(f"\n[+] Ghost file launched! Press Enter to continue.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '3':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    meta = manager.vaultdb.get_meta(uuid, v_ts)
                    confirm = input(f"\nAre you sure you want to delete [{meta['virtual_path']}]? (y/n): ")
                    if confirm.lower() == 'y':
                        try:
                            manager.delete_file(uuid, v_ts)
                            input(f"\n[-] Marked for deletion. Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            elif choice == '4':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    new_path = input("Enter new path (e.g. /Photos/vacation.jpg): ")
                    if new_path:
                        if not new_path.startswith('/'): new_path = '/' + new_path
                        try:
                            manager.rename_file(uuid, v_ts, new_path)
                            input(f"\n[+] Renamed successfully! Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            elif choice == '5':
                selection = explore_vault(manager, include_deleted=True)
                if selection:
                    uuid, v_ts = selection
                    try:
                        manager.reingest_version(uuid, v_ts)
                        input(f"\n[+] Restored successfully! Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}\n{traceback.format_exc()}\nPress Enter.")

            elif choice == '6':
                clear_screen()
                print("\n" + "="*40 + "\n 📜 CURRENT SYNC LEDGER STATE\n" + "="*40)
                try:
                    ledger_data = manager.ledger.get_ledger()
                    if not ledger_data:
                        print("Ledger is currently empty (Fully synced or new).")
                    else:
                        for idx, event in enumerate(ledger_data, 1):
                            uuid, v_ts, action = event
                            meta = manager.vaultdb.get_meta(uuid, v_ts)
                            path = meta['virtual_path'] if meta else "UNKNOWN"
                            print(f"{idx}. [{action}] {uuid.hex()[:8]}... | TS: {v_ts} | Path: {path}")
                except Exception as e:
                    print(f"[!] Could not read ledger: {e}")
                input("\nPress Enter to return.")

            elif choice == '7':
                dyn_manager = VaultDynamicManager(manager)
                print("\n" + "="*40 + "\n 🧹 RUNNING DEFRAGMENTATION\n" + "="*40)
                try:
                    dyn_manager.run_vacuum()
                    input("\n[+] Defragmentation complete! Vault remains open. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error during defragmentation: {e}\n{traceback.format_exc()}\nPress Enter.")
                    manager = None # Crash failsafe

            elif choice == '8':
                dyn_manager = VaultDynamicManager(manager)
                print("\n" + "="*40 + "\n 🔑 ROTATING TITANIUM DEK\n" + "="*40)
                mp, wp = input("Enter Current Master Password: "), input("Enter Current Weak PIN: ")
                
                try:
                    dyn_manager.rotate_titanium_dek(mp, wp)
                    input("\n[+] Master Key Rotated! Vault LOCKED for security. Press Enter.")
                    manager = None
                    active_vault_path = ""
                except Exception as e:
                    input(f"\n[!] Error rotating key: {e}\n{traceback.format_exc()}\nPress Enter.")
                    manager = None # Ensures loop resets if surgeon fails

            elif choice == '9':
                dyn_manager = VaultDynamicManager(manager)
                print("\n" + "="*40 + "\n 🔄 CHANGING VAULT PASSWORD\n" + "="*40)
                old_mp = input("Enter Current Master Password: ")
                old_wp = input("Enter Current Weak PIN: ")
                
                print("-" * 40)
                new_mp = input("Enter NEW Master Password: ")
                new_wp = input("Enter NEW Weak PIN: ")
                
                try:
                    dyn_manager.change_vault_password(old_mp, old_wp, new_mp, new_wp)
                    input("\n[+] Password successfully changed! Vault remains active. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error changing password: {e}\nPress Enter.")
                    
            elif choice == '10':
                manager.lock_vault()
                input("\n[*] Vault locked. RAM shredded. Ledger encrypted. Press Enter.")
                manager = None
                active_vault_path = ""

            elif choice == '11':
                
                if not hasattr(manager, 'skewer'):
                    manager.skewer = TaSkewer(manager)
                    
                worker = SyncWorker(manager)
                
                clear_screen()
                print("\n" + "="*40 + "\n 🌐 NETWORK SYNC ENGINE\n" + "="*40)
                print(f"Local Identity: {worker.local_name} ({worker.local_type})")
                
                # This automatically boots the mDNS broadcast and the socket listener
                worker.start()
                print("[+] Vault Listener & mDNS Broadcast Active.")
                
                print("\n1. Wait for incoming connection (Server)")
                print("2. Scan Network for Peers (Client)")
                print("3. Return to Main Menu")
                net_choice = input("\nSelect option: ")
                
                if net_choice == '1':
                    print("\n[*] Waiting for peer connections... (Press Ctrl+C to abort)")
                    try:
                        while True: time.sleep(1)
                    except KeyboardInterrupt:
                        worker.stop()
                        
                elif net_choice == '2':
                    print("\n[*] Scanning local network for SecureVault peers via mDNS (5 seconds)...")
                    
                    # 1. Call your actual discovery method!
                    peers = worker.discovery.scan_for_devices(scan_time_seconds=5) 
                    
                    if not peers:
                        input("\n[-] No peers found on the local network. Press Enter.")
                        worker.stop()
                        continue
                        
                    print("\n[+] Discovered Peers:")
                    peer_list = list(peers.items()) 
                    
                    # 2. Parse your specific dictionary structure
                    for idx, (raw_name, data) in enumerate(peer_list, 1):
                        display_name = raw_name.replace("._securevault._tcp.local.", "")
                        short_hash = data['ML-DSA-HASH'][:8] if data['ML-DSA-HASH'] else "EMPTY!"
                        print(f"  {idx}. {display_name} ({data['ip']}:{data['port']}) [Hash: {short_hash}...]")
                    print("  0. Cancel")
                    
                    p_choice = input("\nSelect a peer to connect to: ")
                    if p_choice == '0' or not p_choice.isdigit() or int(p_choice) < 1 or int(p_choice) > len(peer_list):
                        worker.stop()
                        continue
                        
                    # 3. Extract the routing and cryptographic data
                    selected_name, selected_data = peer_list[int(p_choice) - 1]
                    target_ip = selected_data["ip"]
                    target_port = selected_data["port"]
                    
                    # 4. FIX: Use the adapter to convert the Hex String back to 32 Raw Bytes!
                    raw_hash_string = selected_data["ML-DSA-HASH"]
                    expected_mdns_hash = hashing.hash_convert_bytes(raw_hash_string)
                    
                    print(f"\n[*] Initiating zero-trust connection to {target_ip}:{target_port}...")
                    
                    # 5. Fire the connection!
                    worker._route_outbound_connection(target_ip, target_port, expected_mdns_hash)
                    
                    input("\n[+] Sync process ended. Press Enter to continue.")
                    worker.stop()

if __name__ == "__main__":
    run_cli()

    