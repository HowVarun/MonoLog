import os
import time
from modules.orchestrator import VaultManager
from modules.daemons import Defragmentation 

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
        
        for path in active_files:
            if path.startswith(current_dir):
                remainder = path[len(current_dir):]
                if "/" in remainder:
                    folder_name = remainder.split("/")[0]
                    folders.add(folder_name)
                elif remainder:
                    files.append(remainder)
                    
        folders = sorted(list(folders))
        files = sorted(files)
        
        print("\n" + "="*40)
        print(f" 📂 SELECT FILE: {current_dir}")
        print("="*40)
        print("0. [.. Go Back / Cancel]")
        
        item_map = {}
        index = 1
        
        for f in folders:
            print(f"{index}. 📁 {f}/")
            item_map[str(index)] = {"type": "dir", "name": f}
            index += 1
            
        for f in files:
            print(f"{index}. 📄 {f}")
            item_map[str(index)] = {"type": "file", "name": f}
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
                return current_dir + selected["name"]

def pick_directory(manager):
    """Interactive explorer for choosing where to save a new file."""
    current_dir = "/"
    
    while True:
        clear_screen()
        active_files = manager.vaultdb.get_active_files()
        
        folders = set()
        for path in active_files:
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
# Main Menus
# ==========================================
def main_menu():
    clear_screen()
    print("\n" + "="*40)
    print(" 🛡️  SECURE VAULT - TERMINAL INTERFACE  ")
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
    print("1. Add a File (Interactive Ingest)")
    print("2. Preview / Launch a File")
    print("3. Delete a File")
    print("4. Vacuum (Defragment)")
    print("5. Lock & Close Vault")
    return input("Select an option: ")

def run_cli():
    manager = None
    active_vault_path = ""

    while True:
        if not manager:
            choice = main_menu()
            
            if choice == '1':
                path = input("\nEnter new vault filename (e.g., my_vault.scaf): ")
                active_vault_path = os.path.join("venv", "Vaults", path)
                os.makedirs(os.path.dirname(active_vault_path), exist_ok=True)
                
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
                path = input("\nEnter existing vault filename: ")
                active_vault_path = os.path.join("venv", "Vaults", path)
                
                if not os.path.exists(active_vault_path):
                    input("\n[!] Vault not found. Press Enter.")
                    continue
                    
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
                v_path = explore_vault(manager)
                if v_path:
                    print(f"\n[*] Decrypting and launching [{v_path}] in ghost mode...")
                    try:
                        # [+] NEW: Hooking directly into your GhostFileIO logic
                        manager.preview_file(v_path)
                        input(f"\n[+] Ghost file launched! Press Enter to continue.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '3':
                v_path = explore_vault(manager)
                if v_path:
                    confirm = input(f"\nAre you sure you want to delete [{v_path}]? (y/n): ")
                    if confirm.lower() == 'y':
                        try:
                            manager.vaultdb.delete_file(v_path, int(time.time()))
                            input(f"\n[-] {v_path} marked for deletion. Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '4':
                print("\n[*] Initiating Defragmentation. Shredding dead space...")
                try:
                    defragger = Defragmentation(manager)
                    defragger.vacuum()
                    input("\n[+] Vacuum complete. Dead space destroyed. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error: {e}. Press Enter.")

            elif choice == '5':
                manager.lock_vault()
                input("\n[*] Vault locked. RAM shredded. Press Enter.")
                manager = None
                active_vault_path = ""

if __name__ == "__main__":
    run_cli()