import queue
import threading
import traceback

from modules.system import LocalOpcodes
from modules.orchestrator import VaultDynamicManager

class TaSkewer:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.task_queue = queue.Queue()
        self.running = True
        
        # Launch dedicated background worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, name="TaSkewerWorker", daemon=True)
        self.worker_thread.start()

    def push(self, opcode: bytes, **kwargs):
        if not self.running:
            raise RuntimeError("TaSkewer thread has been stopped. Cannot accept new tasks.")
            
        self.task_queue.put({"opcode": opcode, "kwargs": kwargs})

    def stop(self):
        """Safely drains remaining tasks and terminates the background thread."""
        self.running = False
        # Push a sentinel poison pill to wake up queue wait if idle
        self.task_queue.put(None)
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=3.0)

    def _process_queue(self):
        """Main event loop executing tasks sequentially."""
        while self.running:
            try:
                # 1. Try to get a task (timeout allows the loop to check self.running)
                task = self.task_queue.get(timeout=0.5)
            except queue.Empty:
                continue
                
            # 2. Handle the Poison Pill (Shutdown)
            if task is None:
                self.task_queue.task_done()
                break
                
            # 3. Execute the Task with a STRICT Finally block
            try:
                opcode = task.get("opcode")
                args = task.get("kwargs", {})
                
                self._dispatch(opcode, args)
                
            except Exception as e:
                print(f"\n[!] Critical error in TaSkewer queue processor: {e}")
                traceback.print_exc()
                
            finally:
                # THE FIX: This executes NO MATTER WHAT, guaranteeing the CLI never freezes.
                self.task_queue.task_done()

    def _dispatch(self, opcode: bytes, args: dict):
        """Routes opcodes strictly to their target methods."""
        
        # =====================================================================
        # CATEGORY Q1: EVERYDAY LOCAL I/O
        # =====================================================================
        if opcode == LocalOpcodes.LOCAL_INGEST:
            self.orchestrator.ingest_file(
                os_filepath=args["source_path"],
                virtual_filepath=args["virtual_path"],
                existing_uuid=args.get("existing_uuid"),
                existing_v_ts=args.get("existing_v_ts")
            )

        elif opcode == LocalOpcodes.LOCAL_EDIT:
            self.orchestrator.reingest_edit(
                ghost_filepath=args["ghost_filepath"],
                original_hash=args["original_hash"],
                uuid=args["uuid"],
                active_v_ts=args["active_v_ts"],
                ghost_io=args["ghost_io"]
            )

        elif opcode == LocalOpcodes.LOCAL_DELETE:
            self.orchestrator.delete_file(
                uuid=args["uuid"],
                v_ts=args["v_ts"]
            )

        elif opcode == LocalOpcodes.LOCAL_RENAME:
            self.orchestrator.rename_file(
                uuid=args["uuid"],
                v_ts=args["v_ts"],
                new_virtual_path=args["new_virtual_path"]
            )

        elif opcode == LocalOpcodes.LOCAL_FORK:
            
            self.orchestrator.fork_conflicted_copy(
                uuid=args["uuid"],
                active_v_ts=args["active_v_ts"]
            )

        elif opcode == LocalOpcodes.LOCAL_RESTORE:
            self.orchestrator.reingest_edit(
                uuid=args["uuid"],
                active_v_ts=args.get("active_v_ts", 0),
                archived_v_ts=args["archived_v_ts"]
            )

        elif opcode == LocalOpcodes.LOCAL_MARK_SYNC:
            self.orchestrator.ledger.mark_synced(
                uuid=args["uuid"],
                data_ts=args["data_ts"],
                meta_ts=args["meta_ts"],
                is_del=args.get("is_del", False)
            )

        # =====================================================================
        # CATEGORY Q2: NETWORK INBOUND / OUTBOUND DATA
        # =====================================================================
        elif opcode == LocalOpcodes.NET_DEL:
            self.orchestrator.delete_file(
                uuid=args["uuid"],
                v_ts=args.get("local_v_ts", 0),
                override_v_ts=args["remote_v_ts"]
            )

        elif opcode == LocalOpcodes.NET_META:
            self.orchestrator.rename_file(
                uuid=args["uuid"],
                v_ts=args.get("local_v_ts", 0),
                new_virtual_path=args["new_virtual_path"],
                override_v_ts=args["remote_v_ts"]
            )

        elif opcode == LocalOpcodes.NET_DATA:
            self.orchestrator.ingest_network_payload(
                tmp_filepath=args["tmp_filepath"],
                virtual_filepath=args["virtual_path"],
                uuid=args["uuid"],
                remote_v_ts=args["remote_v_ts"],
                local_v_ts=args.get("local_v_ts", 0),
                incoming_hashmap=args["hashmap"],
                created_at=args.get("created_at")
            )
            
        elif opcode == LocalOpcodes.LOCAL_MARK_SYNC:
            self.orchestrator.ledger.mark_synced(
                args["uuid"],
                args["v_ts"]
            )

        # =====================================================================
        # CATEGORY Q3: SURGICAL / DEK / AUTH OPERATIONS
        # =====================================================================
        elif opcode == LocalOpcodes.VACUUM:
            surgeon = VaultDynamicManager(self.orchestrator)
            surgeon.run_vacuum()

        elif opcode == LocalOpcodes.CHANGE_PASS:
            surgeon = VaultDynamicManager(self.orchestrator)
            surgeon.change_vault_password(
                old_mp=args["old_mp"],
                old_wp=args["old_wp"],
                new_mp=args["new_mp"],
                new_wp=args["new_wp"]
            )

        elif opcode == LocalOpcodes.ROTATE_DEK:
            print("[!] EXECUTING SEVER & ISOLATE PROTOCOL via TaSkewer...")
            surgeon = VaultDynamicManager(self.orchestrator)
            surgeon.rotate_titanium_dek(
                master_password=args["master_pass"],
                weak_password=args["weak_pass"]
            )
            
            # Wipe trust database physically from memory/disk
            if hasattr(self.orchestrator, 'vaultdb') and self.orchestrator.vaultdb:
                self.orchestrator.vaultdb.purge_inactive_files()
            
            print("[*] Titanium DEK rotation completed. Vault isolated.")

        else:
            print(f"[!] Unrecognized LocalOpcode received: {opcode}")