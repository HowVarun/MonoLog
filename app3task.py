print("1. Importing OS...")
import os
import time
import traceback

print("2. Importing Orchestrator...")
from modules.orchestrator import VaultManager

print("3. Importing TaSkewer...")
from modules.daemons import TaSkewer

print("4. Importing Opcodes...")
from modules.system import LocalOpcodes

print("5. Launching App...")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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
    skewer = None
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
                    skewer = TaSkewer(manager)
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
                    skewer = TaSkewer(manager)
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
                    print("\n[*] Queuing Ingest...")
                    skewer.push(LocalOpcodes.LOCAL_INGEST, source_path=source, virtual_path=v_path)
                    skewer.task_queue.join()
                    input(f"\n[+] Task Completed. Press Enter.")

            elif choice == '2':
                # Reads are instantaneous and don't mutate state, so they bypass the queue
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
                        print("\n[*] Queuing Delete...")
                        skewer.push(LocalOpcodes.LOCAL_DELETE, uuid=uuid, v_ts=v_ts)
                        skewer.task_queue.join()
                        input(f"\n[-] Task Completed. Press Enter.")
                            
            elif choice == '4':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    new_path = input("Enter new path (e.g. /Photos/vacation.jpg): ")
                    if new_path:
                        if not new_path.startswith('/'): new_path = '/' + new_path
                        print("\n[*] Queuing Rename...")
                        skewer.push(LocalOpcodes.LOCAL_RENAME, uuid=uuid, v_ts=v_ts, new_virtual_path=new_path)
                        skewer.task_queue.join()
                        input(f"\n[+] Task Completed. Press Enter.")
                            
            elif choice == '5':
                selection = explore_vault(manager, include_deleted=True)
                if selection:
                    uuid, v_ts = selection
                    print("\n[*] Queuing Restore...")
                    skewer.push(LocalOpcodes.LOCAL_RESTORE, uuid=uuid, v_ts=v_ts)
                    skewer.task_queue.join()
                    input(f"\n[+] Task Completed. Press Enter.")

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
                print("\n" + "="*40 + "\n 🧹 RUNNING DEFRAGMENTATION\n" + "="*40)
                skewer.push(LocalOpcodes.VACUUM)
                skewer.task_queue.join()
                input("\n[+] Task Completed. Press Enter.")

            elif choice == '8':
                print("\n" + "="*40 + "\n 🔑 ROTATING TITANIUM DEK\n" + "="*40)
                mp, wp = input("Enter Current Master Password: "), input("Enter Current Weak PIN: ")
                skewer.push(LocalOpcodes.ROTATE_DEK, master_pass=mp, weak_pass=wp)
                skewer.task_queue.join()
                input("\n[+] Task Completed. Vault locked. Press Enter.")
                manager = None
                skewer = None
                active_vault_path = ""
                
            elif choice == '9':
                print("\n" + "="*40 + "\n 🔄 CHANGING VAULT PASSWORD\n" + "="*40)
                old_mp, old_wp = input("Current Master Password: "), input("Current Weak PIN: ")
                new_mp, new_wp = input("NEW Master Password: "), input("NEW Weak PIN: ")
                skewer.push(LocalOpcodes.CHANGE_PASS, old_mp=old_mp, old_wp=old_wp, new_mp=new_mp, new_wp=new_wp)
                skewer.task_queue.join()
                input("\n[+] Task Completed. Press Enter.")

            elif choice == '10':
                if skewer:
                    skewer.stop(force=False)
                manager.lock_vault()
                input("\n[*] Vault locked. RAM shredded. Ledger encrypted. Press Enter.")
                manager = None
                skewer = None
                active_vault_path = ""

if __name__ == "__main__":
    run_cli()