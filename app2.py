import os
import time
import traceback
from modules.orchestrator import VaultManager
from modules.daemons import SyncWorker, TaSkewer
from modules.system import LocalOpcodes
from modules.crypto_core import hashing, AesGcm
from modules.system.ghostfile import GhostFileIO  # Adjust import path if GhostFileIO is in another submodule



def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


# ==========================================
# The Virtual Directory Explorers
# ==========================================
def explore_vault(manager, include_deleted=False):
    current_dir = "/"
    
    while True:
        clear_screen()
        active_list = manager.vaultdb.get_active_files()
        active_uuids = {u for u, _ in active_list}
        
        if include_deleted:
            # Only show files that are NOT currently active, and pick the latest v_ts per UUID
            latest_deleted = {}
            for row in manager.vaultdb.get_complete_meta():
                u, ts, is_act = row['uuid'], row['v_ts'], row['is_active']
                if not is_act and u not in active_uuids:
                    if u not in latest_deleted or ts > latest_deleted[u]:
                        latest_deleted[u] = ts
            target_files = [(u, ts) for u, ts in latest_deleted.items()]
        else:
            target_files = active_list
        
        folders = set()
        files = []
        
        for uuid, v_ts in target_files:
            meta = manager.vaultdb.get_meta(uuid, v_ts)
            if not meta or not meta.get('virtual_path'):
                continue
            # Strip .del_<timestamp> suffix when browsing deleted files
            path = meta['virtual_path'].split('.del_')[0] if include_deleted else meta['virtual_path']
            
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
        mode = "DELETED FILES" if include_deleted else "ACTIVE FILES"
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
            
        choice = input("\nSelect a number: ").strip()
        
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
    current_dir = "/"
    while True:
        clear_screen()
        active_files = manager.vaultdb.get_active_files()
        
        folders = set()
        for uuid, v_ts in active_files:
            meta = manager.vaultdb.get_meta(uuid, v_ts)
            if not meta:
                continue
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
            
        choice = input("\nSelect a number: ").strip()
        
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
# Ghost File Launch & Edit Helper
# ==========================================
def open_and_track_ghost_file(manager, uuid: bytes, v_ts: int):
    """Decrypts file via GhostFileIO, launches it, and pushes LOCAL_EDIT on close."""
    import hashlib
    
    meta = manager.vaultdb.get_meta(uuid, v_ts)
    chunks = manager.hashmap.get_meta(uuid, v_ts)

    
    
    if not meta or not chunks:
        raise FileNotFoundError("File metadata or chunks missing in vault.")

    ghost_io = GhostFileIO()
    filename = os.path.basename(meta['virtual_path'])
    ghost_path = ghost_io.create_ghost_path(filename)

    local_aes = AesGcm(manager.dek)
    with manager.io_lock:
        for chunk in chunks:
            ct = manager.vaultio.read_cargo(chunk['start'], chunk['end'])
            pt = local_aes.decrypt_cipherstream(chunk['iv'], ct)
            ghost_io.write_decrypted_chunk(ghost_path, pt)



    # ADDED TRACKERS HERE
    with open(ghost_path, 'rb') as f:
        original_hash = hashlib.sha256(f.read()).digest()
    original_mtime = os.path.getmtime(ghost_path)
    original_size = os.path.getsize(ghost_path)

    print(f"\n[*] Launching [{filename}] at: {ghost_path}")
    ghost_io.launch_file(ghost_path)
    
    input("\n[!] Save your edits in the editor, close it, and press Enter here...")
    
    manager.skewer.push(
        LocalOpcodes.LOCAL_EDIT,
        ghost_filepath=ghost_path,
        original_hash=original_hash,
        original_mtime=original_mtime,
        original_size=original_size,
        uuid=uuid,
        active_v_ts=v_ts,
        ghost_io=ghost_io
    )
    manager.skewer.task_queue.join()


# ==========================================
# Peer Discovery & Trusted Device Manager
# ==========================================
def scan_and_connect_peer(worker: SyncWorker, is_clone_mode: bool = False):
    print("\n[*] Scanning local network for SecureVault peers via mDNS (5 seconds)...")
    peers = worker.discovery.scan_for_devices(scan_time_seconds=5)
    
    if not peers:
        input("\n[-] No peers found on the local network. Press Enter.")
        return False
        
    print("\n" + "="*55)
    print(" 📡 DISCOVERED PEERS ON NETWORK")
    print("="*55)
    peer_list = list(peers.items())
    
    for idx, (raw_name, data) in enumerate(peer_list, 1):
        display_name = raw_name.replace("._securevault._tcp.local.", "")
        raw_hash_str = data.get('ML-DSA-HASH', '')
        short_hash = raw_hash_str[:8] if raw_hash_str else "EMPTY"
        
        status_tag = "NEW / UNPAIRED"
        if not is_clone_mode and raw_hash_str:
            peer_bytes = hashing.hash_convert_bytes(raw_hash_str)
            if worker.peers.check_if_compromised(peer_bytes):
                status_tag = "☠️ COMPROMISED (WILL WIPE)"
            else:
                trust_info = worker.peers.is_device_trusted(peer_bytes, worker.vault_id)
                if trust_info:
                    nick = trust_info.get('nickname') or trust_info.get('device_name')
                    paused = " [PAUSED]" if trust_info.get('is_paused') == 1 else ""
                    status_tag = f"✅ TRUSTED ({nick}){paused}"
                    
        print(f"  {idx}. {display_name} ({data['ip']}:{data['port']}) [{short_hash}...] -> {status_tag}")
    print("  0. Cancel")
    
    p_choice = input("\nSelect a peer to connect to: ").strip()
    if p_choice == '0' or not p_choice.isdigit() or not (1 <= int(p_choice) <= len(peer_list)):
        return False
        
    _, selected_data = peer_list[int(p_choice) - 1]
    target_ip = selected_data["ip"]
    target_port = selected_data["port"]
    expected_mdns_hash = hashing.hash_convert_bytes(selected_data["ML-DSA-HASH"])
    
    print(f"\n[*] Initiating zero-trust connection to {target_ip}:{target_port}...")
    status = worker._route_outbound_connection(target_ip, target_port, expected_mdns_hash)
    
    if status == "UNPAIRED_BY_PEER":
        retry = input("\n[!] Error connecting: Most likely the peer removed you from pairing. Wish to re-pair now? (y/n): ").strip().lower()
        if retry == 'y':
            print(f"\n[*] Re-initiating connection to {target_ip}:{target_port} for Re-Pairing...")
            worker._route_outbound_connection(target_ip, target_port, expected_mdns_hash)
            
    return True


def manage_trusted_devices_menu(worker: SyncWorker):
    while True:
        clear_screen()
        vault_id = worker.vault_id
        
        # 1. Get peers for CURRENT vault (Options 1, 2, 3)
        vault_peers = worker.peers.get_vault_peers(vault_id)
        peers_dict = {p['ml_dsa_hash']: p for p in vault_peers}
        peers = list(peers_dict.values())

        # 2. Get ALL peers EVER KNOWN (Options 4, 5)
        raw_peers_data = worker.peers.get_all_peers()
        raw_peers_dict = {rp['ml_dsa_hash']: rp for rp in raw_peers_data}
        raw_peers = list(raw_peers_dict.values())

        # --- MAIN MENU ---
        print("\n" + "="*55)
        print(" ⚙️  TRUSTED DEVICES MANAGER")
        print("="*55)
        print("1. Set Device Nickname (Current Vault)")
        print("2. Pause / Resume Sync (Current Vault)")
        print("3. Soft-Unpair a Device (Current Vault)")
        print("4. ☠️  Mark Device as COMPROMISED (Global)")
        print("5. 🛡️  Remove COMPROMISED Flag (Global)")
        print("0. Back")
        
        sub = input("\nSelect option: ").strip()
        if sub == '0':
            break
        if sub not in ('1', '2', '3', '4', '5'):
            continue
            
        # --- SMART LIST SELECTION ---
        use_global_list = sub in ('4', '5')
        active_list = raw_peers if use_global_list else peers
        list_title = "ALL KNOWN DEVICES (Global)" if use_global_list else "TRUSTED DEVICES (Current Vault)"
        
        # --- PRINT THE SELECTED LIST ---
        print("\n" + "="*55)
        print(f" 🤝 {list_title}")
        print("="*55)
        
        if not active_list:
            input("   (No devices found in this category). Press Enter.")
            continue
            
        for idx, p in enumerate(active_list, 1):
            nick = p.get('nickname') or p.get('device_name') or "Unknown"
            dev_type = p.get('device_type') or "Unknown OS"
            short_h = p['ml_dsa_hash'].hex()[:8]
            
            if p.get('is_compromised') == 1:
                state = "☠️ COMPROMISED"
            elif p.get('is_paused') == 1:
                state = "⏸️ PAUSED"
            else:
                state = "🟢 ACTIVE"
                
            last_s = int(p.get('last_seen', 0))
            last_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_s)) if last_s > 0 else "Never"
            print(f"  {idx}. [{state}] {nick} ({dev_type}) | Hash: {short_h}... | Last Sync: {last_str}")

        print("-" * 55)
        
        # --- GET TARGET DEVICE ---
        idx_str = input("Select device number (0 to cancel): ").strip()
        if idx_str == '0' or not idx_str.isdigit() or not (1 <= int(idx_str) <= len(active_list)):
            continue
            
        # Safely extract from the list we just printed
        target_peer = active_list[int(idx_str) - 1]
        t_hash = target_peer['ml_dsa_hash']
        t_name = target_peer.get('nickname') or target_peer.get('device_name')

        # --- EXECUTE ACTION ---
        if sub == '1':
            new_nick = input(f"Enter new nickname for [{t_name}]: ").strip()
            if new_nick:
                worker.peers.set_nickname(t_hash, vault_id, new_nick)
                input("[+] Nickname updated. Press Enter.")
                
        elif sub == '2':
            currently_paused = (target_peer.get('is_paused') == 1)
            worker.peers.set_pause_state(t_hash, vault_id, not currently_paused)
            state_lbl = "RESUMED" if currently_paused else "PAUSED"
            input(f"[+] Sync {state_lbl} for [{t_name}]. Press Enter.")
            
        elif sub == '3':
            confirm = input(f"Soft-unpair [{t_name}]? (y/n): ").strip().lower()
            if confirm == 'y':
                worker.peers.remove_peer(t_hash, vault_id)
                input(f"[-] [{t_name}] unpaired. Press Enter.")
                
        elif sub == '4':
            confirm = input(f"⚠️ DANGER: Flag [{t_name}] as COMPROMISED? Next time it connects, its vault will self-destruct! (y/n): ").strip().lower()
            if confirm == 'y':
                worker.peers.mark_device_compromised(t_hash)
                input(f"[☠️] Dead Man's Switch ARMED for [{t_name}]. Press Enter.")
                
        elif sub == '5':
            confirm = input(f"Disarm Dead Man's Switch for [{t_name}]? (y/n): ").strip().lower()
            if confirm == 'y':
                worker.peers.remove_compromise_flag(t_hash)
                input(f"[+] Dead Man's Switch DISARMED for [{t_name}]. Press Enter.")
# ==========================================
# Main Menus
# ==========================================
def main_menu():
    clear_screen()
    node_id = os.getenv("SV_NODE", "1")
    print("\n" + "="*45)
    print(f" 🛡️  MONOLOG VAULT (Node {node_id}) ")
    print("="*45)
    print("1. Create New Vault")
    print("2. Unlock Existing Vault")
    print("3. Clone / Import Vault from Peer (Network)")
    print("4. Exit")
    return input("Select an option: ").strip()


def vault_menu(vault_path):
    clear_screen()
    print("\n" + "="*45)
    print(f" 🔓 ACTIVE VAULT: {os.path.basename(vault_path)}")
    print("="*45)
    print("1. Add a File (Ingest)")
    print("2. Open / Edit a File (Ghost Mode)")
    print("3. Delete a File")
    print("4. Rename a File")
    print("5. Restore a Deleted / Archived Version")
    print("6. View Network Sync Ledger")
    print("7. Run Defragmentation (Vacuum)")
    print("8. Rotate Master Encryption Key (Sever & Isolate)")
    print("9. Change Vault Password")
    print("10. Lock & Close Vault")
    print("11. Network Sync, Pairing & Device Manager")
    return input("Select an option: ").strip()


def run_cli():
    manager = None
    active_vault_path = ""
    vaults_dir = "Vaults"
    os.makedirs(vaults_dir, exist_ok=True)

    ACTION_NAMES = {
        0: "DELETE",
        1: "RENAME",
        2: "EDIT",
        3: "INGEST"
    }

    while True:
        if not manager:
            choice = main_menu()
            
            # 1. CREATE NEW VAULT
            if choice == '1':
                path = input("\nEnter new vault filename (e.g., test.scaf): ").strip()
                if not path:
                    continue
                if not path.endswith('.scaf'):
                    path += '.scaf'
                active_vault_path = os.path.join(vaults_dir, path)
                mp = input("Enter Master Password: ")
                wp = input("Enter Weak PIN: ")
                
                manager = VaultManager(active_vault_path)
                try:
                    manager.create_new_vault(mp, wp)
                    manager.skewer = TaSkewer(manager)
                    input("\n[+] Vault created and unlocked! Press Enter to continue.")
                except Exception as e:
                    print(f"\n[!] Error: {e}")
                    manager = None
                    time.sleep(2)

            # 2. UNLOCK EXISTING VAULT
            elif choice == '2':
                existing_vaults = [f for f in os.listdir(vaults_dir) if f.endswith('.scaf')]
                if not existing_vaults:
                    input(f"\n[!] No .scaf vaults found in '{vaults_dir}'. Press Enter.")
                    continue
                
                print("\n[*] Available Vaults:")
                for idx, v_name in enumerate(existing_vaults, 1):
                    print(f"  {idx}. {v_name}")
                print("  0. Cancel")
                
                v_choice = input("\nSelect a vault number: ").strip()
                if v_choice == '0' or not v_choice.isdigit() or not (1 <= int(v_choice) <= len(existing_vaults)):
                    continue
                    
                active_vault_path = os.path.join(vaults_dir, existing_vaults[int(v_choice) - 1])
                mp = input("Enter Master Password: ")
                wp = input("Enter Weak PIN: ")
                
                manager = VaultManager(active_vault_path)
                try:
                    manager.unlock_hash(mp, wp)
                    manager.boot_vault()
                    manager.skewer = TaSkewer(manager)
                    input("\n[+] Vault unlocked! Press Enter to continue.")
                except Exception as e:
                    print(f"\n[!] Error unlocking vault: {e}")
                    manager = None
                    time.sleep(2)

            # 3. CLONE VAULT FROM PEER (DASHBOARD MODE - NO UNLOCKED VAULT)
            elif choice == '3':
                path = input("\nEnter destination filename for cloned vault (e.g., cloned.scaf): ").strip()
                if not path:
                    continue
                if not path.endswith('.scaf'):
                    path += '.scaf'
                active_vault_path = os.path.join(vaults_dir, path)
                
                # Instantiate unbooted VaultManager (dek is None -> triggers PRE_VAULT_SETUP & wants_clone=True)
                temp_manager = VaultManager(active_vault_path)
                worker = SyncWorker(temp_manager)
                worker.start()
                
                try:
                    connected = scan_and_connect_peer(worker, is_clone_mode=True)
                    if connected and getattr(temp_manager, 'dek', None):
                        # Clone succeeded and booted inside _execute_pairing_client!
                        if not getattr(temp_manager, 'skewer', None):
                            temp_manager.skewer = TaSkewer(temp_manager)
                        manager = temp_manager
                        input("\n[+] Cloned Vault is now active! Press Enter to enter Vault Menu.")
                    else:
                        input("\n[-] Clone session ended without importing a vault. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Clone Error: {e}\nPress Enter.")
                finally:
                    worker.stop()

            # 4. EXIT
            elif choice == '4':
                break

        # =========================================================================
        # INSIDE UNLOCKED VAULT MENU
        # =========================================================================
        else:
            if not getattr(manager, 'skewer', None):
                manager.skewer = TaSkewer(manager)

            choice = vault_menu(active_vault_path)
            
            # 1. INGEST FILE
            if choice == '1':
                source = input("\nEnter full path of local file to upload: ").strip().strip('"')
                if not os.path.exists(source):
                    input("[!] Local file not found. Press Enter.")
                    continue
                
                target_dir = pick_directory(manager)
                if target_dir:
                    default_name = os.path.basename(source)
                    v_name = input(f"\nEnter filename for vault (Leave blank to use '{default_name}'): ").strip()
                    if not v_name:
                        v_name = default_name
                        
                    v_path = target_dir + v_name
                    try:
                        manager.skewer.push(
                            LocalOpcodes.LOCAL_INGEST,
                            source_path=source,
                            virtual_path=v_path
                        )
                        manager.skewer.task_queue.join()
                        input(f"\n[+] Added to vault as {v_path}. Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}\n{traceback.format_exc()}\nPress Enter.")

            # 2. OPEN / EDIT IN GHOST MODE
            elif choice == '2':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    try:
                        open_and_track_ghost_file(manager, uuid, v_ts)
                        input("\n[+] Ghost session closed & shredded (edits synced if modified). Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}\n{traceback.format_exc()}\nPress Enter.")

            # 3. DELETE FILE
            elif choice == '3':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    meta = manager.vaultdb.get_meta(uuid, v_ts)
                    confirm = input(f"\nAre you sure you want to delete [{meta['virtual_path']}]? (y/n): ").strip()
                    if confirm.lower() == 'y':
                        try:
                            manager.skewer.push(LocalOpcodes.LOCAL_DELETE, uuid=uuid, v_ts=v_ts)
                            manager.skewer.task_queue.join()
                            input("\n[-] Marked for deletion. Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            # 4. RENAME FILE
            elif choice == '4':
                selection = explore_vault(manager)
                if selection:
                    uuid, v_ts = selection
                    new_path = input("Enter new path (e.g. /Photos/vacation.jpg): ").strip()
                    if new_path:
                        if not new_path.startswith('/'):
                            new_path = '/' + new_path
                        try:
                            manager.skewer.push(
                                LocalOpcodes.LOCAL_RENAME,
                                uuid=uuid,
                                v_ts=v_ts,
                                new_virtual_path=new_path
                            )
                            manager.skewer.task_queue.join()
                            input("\n[+] Renamed successfully! Press Enter.")
                        except Exception as e:
                            input(f"\n[!] Error: {e}. Press Enter.")
                            
            # 5. RESTORE ARCHIVED / DELETED VERSION
            elif choice == '5':
                selection = explore_vault(manager, include_deleted=True)
                if selection:
                    uuid, archived_v_ts = selection
                    try:
                        # Check if there is currently an active version of this UUID
                        active_dict = dict(manager.vaultdb.get_active_files())
                        active_v_ts = active_dict.get(uuid, 0)
                        
                        manager.skewer.push(
                            LocalOpcodes.LOCAL_RESTORE,
                            uuid=uuid,
                            active_v_ts=active_v_ts,
                            archived_v_ts=archived_v_ts
                        )
                        manager.skewer.task_queue.join()
                        input("\n[+] Version restored successfully! Press Enter.")
                    except Exception as e:
                        input(f"\n[!] Error: {e}\n{traceback.format_exc()}\nPress Enter.")

            # 6. VIEW COMPACTED SYNC LEDGER
            elif choice == '6':
                clear_screen()
                print("\n" + "="*65 + "\n 📜 CURRENT COMPACTED SYNC LEDGER\n" + "="*65)
                try:
                    ledger_data = manager.ledger.get_ledger()
                    if not ledger_data:
                        print("Ledger is currently empty.")
                    else:
                        for idx, event in enumerate(ledger_data, 1):
                            uuid, meta_ts, action, data_ts, is_del = event
                            meta = manager.vaultdb.get_meta(uuid, meta_ts)
                            path = meta['virtual_path'] if meta else "DELETED / TOMBSTONE"
                            act_str = ACTION_NAMES.get(action, str(action))
                            print(f"{idx}. [{act_str:<6}] {uuid.hex()[:8]}... | DataTS: {data_ts} | MetaTS: {meta_ts} | Del: {is_del} | {path}")
                except Exception as e:
                    print(f"[!] Could not read ledger: {e}")
                input("\nPress Enter to return.")

            # 7. VACUUM / DEFRAGMENT
            elif choice == '7':
                print("\n" + "="*40 + "\n 🧹 RUNNING DEFRAGMENTATION\n" + "="*40)
                try:
                    manager.skewer.push(LocalOpcodes.VACUUM)
                    manager.skewer.task_queue.join()
                    input("\n[+] Defragmentation complete! Vault remains open. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error during defragmentation: {e}\n{traceback.format_exc()}\nPress Enter.")

            
            # 8. ROTATE TITANIUM DEK + COMPROMISED DEVICE PROMPT
            elif choice == '8':
                print("\n" + "="*45 + "\n 🔑 ROTATING TITANIUM DEK (SEVER & ISOLATE)\n" + "="*45)
                mp = input("Enter Current Master Password: ")
                wp = input("Enter Current Weak PIN: ")
                
                try:
                    # Capture current vault_id and peers BEFORE rotating the DEK changes the vault_id!
                    temp_worker = SyncWorker(manager)
                    temp_worker.peers.create_db() # Failsafe to ensure DB exists
                    old_vault_id = temp_worker.vault_id
                    paired_peers = temp_worker.peers.get_vault_peers(old_vault_id)
                    
                    if not paired_peers:
                        print("\n[*] No paired devices found for this vault.")
                        print("[*] Skipping network isolation prompt (no peers to flag).")
                    else:
                        print("\n" + "-"*45)
                        print(" ⚠️  NETWORK ISOLATION (DEAD MAN'S SWITCH)")
                        print("-" * 45)
                        print("The Master Key is changing. You can flag currently paired")
                        print("devices as COMPROMISED. The next time they connect, their")
                        print("copy of the vault will self-destruct (Nuclear Wipe).")
                        
                        print("\nCurrently Paired Devices:")
                        for idx, p in enumerate(paired_peers, 1):
                            nick = p.get('nickname') or p.get('device_name') or "Unknown"
                            print(f"  {idx}. {nick}")

                        print("\nOptions:")
                        print("  [all]  Nuke ALL devices")
                        print("  [none] Nuke NO devices (just sever connection)")
                        print("  [1,3]  Nuke specific devices (comma-separated)")
                        
                        nuke_choice = input("\nEnter choice (all/none/1,2...): ").strip().lower()
                        
                        if nuke_choice == 'all':
                            for p in paired_peers:
                                temp_worker.peers.mark_device_compromised(p['ml_dsa_hash'])
                            print("[☠️] All previous peers flagged for NUCLEAR_WIPE.")
                            
                        elif nuke_choice != 'none' and nuke_choice:
                            indices = [i.strip() for i in nuke_choice.split(',')]
                            for i_str in indices:
                                if i_str.isdigit():
                                    idx = int(i_str) - 1
                                    if 0 <= idx < len(paired_peers):
                                        t_hash = paired_peers[idx]['ml_dsa_hash']
                                        temp_worker.peers.mark_device_compromised(t_hash)
                                        print(f"[☠️] {paired_peers[idx].get('device_name', 'Device')} flagged for NUCLEAR_WIPE.")

                    manager.skewer.push(LocalOpcodes.ROTATE_DEK, master_pass=mp, weak_pass=wp)
                    manager.skewer.task_queue.join()
                    
                    print("\n[+] Master Key Rotated & Ledger Wiped!")
                    print("[*] Vault is now LOCKED for security. You must re-authenticate with the new password.")
                    input("Press Enter to return to the Main Menu...")
                    
                    # Tear down the session in the UI
                    if getattr(manager, 'skewer', None):
                        manager.skewer.stop()
                    manager = None
                    active_vault_path = ""
                    
                except Exception as e:
                    input(f"\n[!] Error rotating key: {e}\n{traceback.format_exc()}\nPress Enter.")

            # 9. CHANGE VAULT PASSWORD
            elif choice == '9':
                print("\n" + "="*40 + "\n 🔄 CHANGING VAULT PASSWORD\n" + "="*40)
                old_mp = input("Enter Current Master Password: ")
                old_wp = input("Enter Current Weak PIN: ")
                print("-" * 40)
                new_mp = input("Enter NEW Master Password: ")
                new_wp = input("Enter NEW Weak PIN: ")
                
                try:
                    manager.skewer.push(
                        LocalOpcodes.CHANGE_PASS,
                        old_mp=old_mp,
                        old_wp=old_wp,
                        new_mp=new_mp,
                        new_wp=new_wp
                    )
                    manager.skewer.task_queue.join()
                    input("\n[+] Password successfully changed! Vault remains active. Press Enter.")
                except Exception as e:
                    input(f"\n[!] Error changing password: {e}\nPress Enter.")
                    
            # 10. LOCK & CLOSE VAULT
            elif choice == '10':
                if getattr(manager, 'skewer', None):
                    manager.skewer.stop()
                manager.lock_vault()
                input("\n[*] Vault locked. RAM shredded. Ledger encrypted. Press Enter.")
                manager = None
                active_vault_path = ""

            # 11. NETWORK SYNC, PAIRING & DEVICE MANAGER
            elif choice == '11':
                worker = SyncWorker(manager)
                worker.start()
                
                try:
                    while True:
                        clear_screen()
                        print("\n" + "="*50 + "\n 🌐 NETWORK SYNC & PAIRING ENGINE\n" + "="*50)
                        print(f"Local Device : {worker.local_name} ({worker.local_type})")
                        print(f"Listening On : Port {worker.port} (mDNS Active)")
                        print(f"Vault ID     : {worker.vault_id.hex()[:16]}...")
                        print("-" * 50)
                        print("1. Wait for Incoming Connection (Server Mode - Sync / Pair / Serve Clone)")
                        print("2. Scan & Connect to Peer (Client Mode - Auto-Sync if Trusted / Re-Pair if Untrusted)")
                        print("3. Manage Trusted Devices (Nickname / Pause / Unpair / Nuclear Wipe)")
                        print("0. Return to Vault Menu")
                        
                        net_choice = input("\nSelect option: ").strip()
                        
                        if net_choice == '0':
                            break
                        elif net_choice == '1':
                            print("\n[*] Listening for peer connections... (Press Ctrl+C to stop waiting)")
                            try:
                                while True:
                                    time.sleep(1)
                            except KeyboardInterrupt:
                                print("\n[*] Stopped waiting.")
                        elif net_choice == '2':
                            scan_and_connect_peer(worker, is_clone_mode=False)
                            input("\n[*] Network operation finished. Press Enter to continue.")
                        elif net_choice == '3':
                            manage_trusted_devices_menu(worker)
                finally:
                    worker.stop()


if __name__ == "__main__":
    run_cli()