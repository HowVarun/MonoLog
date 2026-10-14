import os 
import socket
import msgpack
import subprocess
import concurrent.futures
import tempfile
import platform
import threading
import json
import time
import struct

from modules.system import Opcodes, LocalOpcodes
from modules.network import DesktopDiscover, SecureNetworkTransport, TrustedDevicesDatabase
from modules.system import PrivateKeyManager
from modules.crypto_core import hashing, SasPass

class SecurityError(Exception):
    pass

class SyncWorker:
    def __init__(self, vault_manager  ,port: int = 65432, storage_dir=None):
        self.port = port 
        self.dir = storage_dir if storage_dir else tempfile.gettempdir()
        self.vault_manager = vault_manager

        #identity
        self.pvt_key_mgr = PrivateKeyManager()
        self.my_identity = self.pvt_key_mgr.get_or_create_identity()
        self.my_pub_key = bytes(self.my_identity.generate_key("pub"))
        self.peers = TrustedDevicesDatabase(self.dir)
        
        #network classes
        self.discovery = DesktopDiscover()
        
        #device info
        self.local_name, self.local_type = self.get_device_identity()
        self.is_running = False 
        self.server_socket = None
        self._listener = None 
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(5)

        #Pairing states
        self.ui_request_pin_cb = None
        self.ui_display_pin_cb = None
    #==========================================================
    @staticmethod
    def get_device_identity():
        device_name = socket.gethostname()
        if device_name.endswith(".local"):
            device_name = device_name[:-6]
            
        system = platform.system()
        device_type = f"Unknown {system} Device"

        #attempt android detection (Java Native Interface)
        try:
            from jnius import autoclass
            Build = autoclass('android.os.Build')
            device_type = str(Build.MODEL)
            return device_name, device_type
        except ImportError:
            pass 

        #attempt ios detection 
        try:
            from pyobjus import autoclass
            UIDevice = autoclass('UIDevice')
            device_type = str(UIDevice.currentDevice().name.UTF8String())
            return device_name, device_type
        except ImportError:
            pass 

        #desktop os's
        try:
            if system == "Windows":
                cmd = 'powershell "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty Name"'
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
                device_type = result.decode('utf-8').strip()
                
            elif system == "Darwin": 
                result = subprocess.check_output(["sysctl", "-n", "hw.model"], stderr=subprocess.DEVNULL)
                device_type = result.decode('utf-8').strip()
                
            elif system == "Linux":
                filepath_dmi = "/sys/devices/virtual/dmi/id/product_name"
                filepath_dt = "/sys/firmware/devicetree/base/model"
                
                if os.path.exists(filepath_dmi):
                    with open(filepath_dmi, "r") as f:
                        device_type = f.read().strip()
                elif os.path.exists(filepath_dt):
                    with open(filepath_dt, "r") as f:
                        device_type = f.read().strip().strip('\x00')
        except Exception:
            pass

        return device_name, device_type

    #==========================================================
    #pairing ui and cli routing
    def _request_pin(self, peer_name: str) -> str:
        """Attempts UI callback first, falls back to CLI."""
        if self.ui_request_pin_cb:
            try:
                pin = self.ui_request_pin_cb(peer_name)
                if pin: return pin
            except Exception as e:
                print(f"\n[-] UI Pin Request Failed: {e}. Falling back to CLI.")
        
        return self._cli_request_pin(peer_name)

    def _cli_request_pin(self, peer_name: str) -> str:
        return input(f"\n[?] Enter the 6-digit PIN displayed on [{peer_name}]'s screen: ").strip()

    def _display_pin(self, peer_name: str, pin: str):
        """Attempts UI callback first, falls back to CLI."""
        if self.ui_display_pin_cb:
            try:
                self.ui_display_pin_cb(peer_name, pin)
                return
            except Exception as e:
                print(f"\n[-] UI Pin Display Failed: {e}. Falling back to CLI.")
                
        self._cli_display_pin(peer_name, pin)

    def _cli_display_pin(self, peer_name: str, pin: str):
        print(f"\n" + "="*38)
        print(f" 🔐 SECUREVAULT PAIRING REQUEST")
        print(f" Peer: {peer_name}")
        print(f" PIN:  {pin}")
        print("="*38)
        print("[*] Waiting for peer to enter this PIN...")
    

    #==========================================================
    def _opcode_check(self, received_msg: tuple, expected_opcode: bytes, transport: SecureNetworkTransport, fail_opcode: bytes = Opcodes.BYE_FORCE) -> bytes:
        opcode_recv, payload = received_msg
        
        if opcode_recv == expected_opcode:
            return payload
            
        # If they send the wrong thing, send the fail opcode (Defaults to BYE_FORCE)
        transport.send_message(fail_opcode)
        raise ValueError(f"Protocol Violation: Expected {expected_opcode}, got {opcode_recv}")
         
    
    def _verify_rcvd(self, transport : SecureNetworkTransport):
        transport.send_message(Opcodes.ACK_OK)
    
    def _verify_sent(self, transport : SecureNetworkTransport):
        opcode, _ = transport.receive_message()
        if opcode == Opcodes.ACK_OK:
            return True
        else:
            transport.send_message(Opcodes.ACK_FAIL)

    #==========================================================
    def start(self):
        if self.is_running:
            return False
        else:
            self.peers.create_db()
            self.peers.create_db()
            self.discovery.broadcast_presence(self.my_pub_key)

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            
            self.is_running = True
            self._listener = threading.Thread(target=self._network_listener, daemon=True)
            self._listener.start()
    
    def stop(self):
        self.is_running = False
        self.discovery.cleanup()
        self._thread_pool.shutdown(wait=False)
        if self.server_socket:
            self.server_socket.close()
    
    def _network_listener(self):
        while self.is_running:
            try:
                self.server_socket.settimeout(1.0)
                client_sock, addr = self.server_socket.accept()
                client_sock.settimeout(None)
                self._thread_pool.submit(self._route_inbound_connection, client_sock, addr)
            except socket.timeout:
                continue
            except Exception:
                if not self.is_running:
                    break
    
    #===========================================================================================================================
    def _inbound_router(self, transport : SecureNetworkTransport):

        opcode_received, peer_hash = transport.receive_message()

        #==============PROTOCOL ROUTING===============
        if opcode_received == Opcodes.TRUST_QRY:
            peer_data = self.peers.is_device_trusted(peer_hash)

            if peer_data:
                transport.send_message(Opcodes.TRUST_YES)
                self._execute_sync_session(transport, peer_hash, is_client=False)
            else:
                transport.send_message(Opcodes.DEVC_RM)
                self._execute_pairing_server(transport, peer_hash)

        elif opcode_received == Opcodes.DSA_HASH:
            peer_data = self.peers.is_device_trusted(peer_hash)

            if not peer_data:
                transport.send_message(Opcodes.TRUST_NO)
                self._execute_pairing_server(transport, peer_hash)
            elif peer_data:
                transport.send_message(Opcodes.TRUST_YES)
                recv_op, _ = transport.receive_message()
                if recv_op == Opcodes.DEVC_RM:
                    self.peers.remove_peer(peer_hash)
                    transport.send_message(Opcodes.TRUST_RM)
                    self._execute_pairing_server(transport, peer_hash)
            else:
                raise SecurityError("Trusted Devices database compromised")
        
        elif opcode_received == Opcodes.DEVC_RM:
            self.peers.remove_peer(peer_hash)
            transport.send_message(Opcodes.TRUST_RM)
            self._execute_pairing_server(transport, peer_hash)
        else:
            raise ValueError("Did not recieve a valid routing opcode")

    def _route_inbound_connection(self, client_sock: socket.socket, addr: tuple):
        transport = SecureNetworkTransport(sock=client_sock)
        
        try:
            ping_bytes = self._opcode_check(transport.receive_message(), Opcodes.PING, transport)
            transport.send_message(Opcodes.PONG, ping_bytes)
            self._inbound_router(transport)

        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure with {addr[0]}: {e}")
        finally:
            transport.close_connection()
            
    #===========================================================================================================================
    def _outbound_router(self, transport : SecureNetworkTransport, expected_mdns_hash : bytes):
        pub_hash = hashing.hash_key(self.my_pub_key)
        
        is_known = self.peers.is_device_trusted(expected_mdns_hash)

        #==========Routing Protocol=======================
        if is_known:
            transport.send_message(Opcodes.TRUST_QRY, pub_hash)
            opcode, _ = transport.receive_message()
            if opcode == Opcodes.TRUST_YES:
                self._execute_sync_session(transport, expected_mdns_hash, is_client=True)
            elif opcode == Opcodes.DEVC_RM:
                self.peers.remove_peer(expected_mdns_hash)
                transport.send_message(Opcodes.TRUST_RM)
                self._execute_pairing_client(transport, expected_mdns_hash)
            else:
                raise SecurityError("Invalid opcode at current stage")
        else:
            transport.send_message(Opcodes.DSA_HASH, pub_hash)
            opcode, _ = transport.receive_message()
            if opcode == Opcodes.TRUST_NO:
                self._execute_pairing_client(transport, expected_mdns_hash)
            elif opcode == Opcodes.TRUST_YES:
                transport.send_message(Opcodes.DEVC_RM)
                opcode, _ = transport.receive_message()
                if opcode == Opcodes.TRUST_RM:
                    self._execute_pairing_client(transport, expected_mdns_hash)
                else:
                    raise SecurityError("Secondary device not unpaired successfully!")
            else:
                raise SecurityError("Invalid opcode at current stage")
        
    
    def _route_outbound_connection(self, target_ip: str, target_port : int, expected_mdns_hash : bytes):
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client_sock.connect((target_ip, target_port))
            transport = SecureNetworkTransport(sock = client_sock)

            rand_byte = os.urandom(8)
            transport.send_message(Opcodes.PING, rand_byte)
            rcvd_byte = self._opcode_check(transport.receive_message(), Opcodes.PONG, transport)
            if rcvd_byte != rand_byte:
                raise SecurityError("Device transport functionality compromised")
            
            self._outbound_router(transport, expected_mdns_hash)
        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure: {e}")
        finally:
            transport.close_connection()

    #===========================================================================================================================
    def _execute_pairing_server(self, transport : SecureNetworkTransport, peer_hash):
        try:

            #DEBUGGER  : 
            self_key = self.my_pub_key 
            
            print("\n" + "="*40)
            print(f"[SERVER] Sending Key to Client...")
            print(f"[SERVER] Key Head: {self_key[:20].hex()}")
            print(f"[SERVER] Key Tail: {self_key[-20:].hex()}")
            print("="*40 + "\n")

            peer_key = self._opcode_check(transport.receive_message(), Opcodes.DSA_PUB, transport, Opcodes.PUB_ERR)
            transport.send_message(Opcodes.DSA_PUB, self_key)
            
            if not hashing.hash_verify(peer_key, peer_hash):
                transport.send_message(Opcodes.HASH_ERR)
                raise SecurityError("Hash does not match key!")
                
            peer_devc_meta_bytes = self._opcode_check(transport.receive_message(), Opcodes.DEVC_ID, transport, Opcodes.ID_ERR)
            
            try:
                peer_meta = json.loads(peer_devc_meta_bytes.decode('utf-8'))
                peer_name = peer_meta.get("device_name", "Unknown Device")
                peer_type = peer_meta.get("device_type", "Unknown OS")
            except Exception:
                transport.send_message(Opcodes.ID_ERR)
                raise SecurityError("Malformed Metadata payload JSON")
                
            self_devc_meta = {
                "device_name": self.local_name,
                "device_type": self.local_type,
                "app_version": "1.0"
            }
            transport.send_message(Opcodes.DEVC_ID, json.dumps(self_devc_meta).encode('utf-8')) 

            # Request Pin out-of-band on Alice's side (To be replaced by UI Thread-Event later)
            sas_pin = sas_pin = self._request_pin(peer_name)
            
            if SasPass.verify_pass(sas_pin, self_key, peer_key):
                transport.send_message(Opcodes.AUTH_PASS)
                
                opcode, _ = transport.receive_message()
                if opcode == Opcodes.AUTH_PASS:
                    self.peers.add_trusted_device(
                        ml_dsa_hash=peer_hash,
                        device_name=peer_name,
                        device_type=peer_type,
                        ml_dsa_pub_key=peer_key,
                        added_timestamp=time.time(),
                        last_seen=time.time()
                    )
                    transport.send_message(Opcodes.BYE_GRACE)
                else:
                    raise SecurityError("Authentication handshake failed during commitment exchange")
            else:
                transport.send_message(Opcodes.AUTH_FAIL)
                raise SecurityError("SAS PIN Verification Failed!")
                       
        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Pairing failure: {e}")

    #===========================================================================================================================
    def _execute_pairing_client(self, transport : SecureNetworkTransport, peer_hash):
        try:
            self_key = self.my_pub_key
            transport.send_message(Opcodes.DSA_PUB, self_key)
            peer_key = self._opcode_check(transport.receive_message(), Opcodes.DSA_PUB, transport, Opcodes.PUB_ERR)

            if not hashing.hash_verify(peer_key, peer_hash):
                transport.send_message(Opcodes.HASH_ERR)
                raise SecurityError("Hash does not match key!")

            self_devc_meta = {
                "device_name": self.local_name,
                "device_type": self.local_type,
                "app_version": "1.0"
            }
            transport.send_message(Opcodes.DEVC_ID, json.dumps(self_devc_meta).encode('utf-8'))
            
            peer_devc_meta_bytes = self._opcode_check(transport.receive_message(), Opcodes.DEVC_ID, transport, Opcodes.ID_ERR)
            
            try:
                peer_meta = json.loads(peer_devc_meta_bytes.decode('utf-8'))
                peer_name = peer_meta.get("device_name", "Unknown Device")
                peer_type = peer_meta.get("device_type", "Unknown OS")
            except Exception:
                transport.send_message(Opcodes.ID_ERR)
                raise SecurityError("Malformed Metadata payload JSON")

            PIN = SasPass.derive_pass(peer_key, self_key)
            self._display_pin(peer_name, PIN)
            
            opcode, _ = transport.receive_message(timeout=60.0) # Allow up to 1 minute for Alice's input
            
            if opcode == Opcodes.AUTH_PASS:
                self.peers.add_trusted_device(
                    ml_dsa_hash=peer_hash,
                    device_name=peer_name,
                    device_type=peer_type,
                    ml_dsa_pub_key=peer_key,
                    added_timestamp=time.time(),
                    last_seen=time.time()
                )
                transport.send_message(Opcodes.AUTH_PASS)
                self._opcode_check(transport.receive_message(), Opcodes.BYE_GRACE, transport)
            elif opcode == Opcodes.AUTH_FAIL:
                raise SecurityError("ENTERED WRONG SAS PIN")

        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Pairing failure: {e}")

    #===========================================================================================================================
    def _execute_sync_session(self, transport: SecureNetworkTransport, peer_hash: str, is_client: bool):
        if not self.vault_manager or not getattr(self.vault_manager, 'ledger', None):
            transport.send_message(Opcodes.BYE_FORCE)
            return

        import msgpack
        self.ledger = self.vault_manager.ledger

        try:
            # 1. Strict Linear Handshake
            if is_client:
                transport.send_message(Opcodes.SYNCO)
                self._opcode_check(transport.receive_message(), Opcodes.ACQ_OK, transport)
            else:
                self._opcode_check(transport.receive_message(), Opcodes.SYNCO, transport)
                transport.send_message(Opcodes.ACQ_OK)

            # 2. Swap Unsynced Ledgers
            local_unsynced = self.ledger.get_unsynced_payload()
            local_payload = msgpack.packb(local_unsynced, use_bin_type=True)
            
            transport.send_message(Opcodes.SYNC_LDG, local_payload)
            rcvd_opcode, peer_payload = transport.receive_message(timeout=15.0)
            
            if rcvd_opcode != Opcodes.SYNC_LDG:
                raise ValueError("Peer failed to provide Sync Ledger")
                
            peer_unsynced_data = msgpack.unpackb(peer_payload, raw=False)

            # 3. The Turn-Based Sync
            if is_client:
                # Client audits and pulls first
                pull_list = self._auditor(peer_unsynced_data, is_client)
                self._fetcher(transport, pull_list)
                
                # Client becomes the Server
                self._serve_peer_requests(transport)
            else:
                # Server waits and serves first
                self._serve_peer_requests(transport)
                
                # Server gets its turn to pull
                pull_list = self._auditor(peer_unsynced_data, is_client)
                self._fetcher(transport, pull_list)

            # 4. Graceful Teardown
            transport.send_message(Opcodes.BYE_GRACE)

        except Exception as e:
            print(f"[!] Sync Session Error: {e}")
            try:
                transport.send_message(Opcodes.BYE_FORCE)
            except Exception:
                pass

    def _auditor(self, peer_unsynced_data: dict, is_client: bool) -> dict:
        local_full_ledger = self.ledger.get_ledger()
        local_unsynced_uuids = self.ledger.get_unsynced_payload().keys() # Your method!
        
        local_v_ts_map = {}
        for record in local_full_ledger:
            l_uuid = record[0]
            l_v_ts = record[1]
            if l_uuid not in local_v_ts_map or l_v_ts > local_v_ts_map[l_uuid]:
                local_v_ts_map[l_uuid] = l_v_ts

        pull_list = {}
        
        for p_uuid, p_data in peer_unsynced_data.items():
            p_v_ts = p_data[0]
            p_action = p_data[1]
            l_v_ts = local_v_ts_map.get(p_uuid, 0)
            
            #tie breaker logic
            if p_v_ts > l_v_ts or (p_v_ts == l_v_ts and not is_client):
                is_conflict = p_uuid in local_unsynced_uuids
                
                pull_list[p_uuid] = {
                    "action": p_action, 
                    "v_ts": p_v_ts, 
                    "local_v_ts": l_v_ts,
                    "is_conflict": is_conflict
                }
                
        return pull_list


    def _fetcher(self, transport: SecureNetworkTransport, pull_list: dict):

        for p_uuid, data in pull_list.items():
            p_action = data["action"]
            p_v_ts = data["v_ts"]
            l_v_ts = data["local_v_ts"]

            # 1. DELETIONS (Network Bypass)
            if p_action == self.ledger.ACTION_DELETE:
                self.skewer.push(LocalOpcodes.NET_DEL, uuid=p_uuid, local_v_ts=l_v_ts, remote_v_ts=p_v_ts)
                self.skewer.push(LocalOpcodes.LOCAL_MARK_SYNC, uuid=p_uuid, v_ts=p_v_ts)
                continue

            # 2. REQUEST DATA FROM PEER
            transport.send_message(Opcodes.SYNC_REQ, p_uuid)
            opcode, payload = transport.receive_message(timeout=30.0)

            if opcode in (Opcodes.SYNC_ERR, Opcodes.SYNC_NUL):
                continue  

            # 3. PROCESS INCOMING METADATA AND FILE HEADERS
            if opcode == Opcodes.VAULT_META:
                try:
                    header_file = msgpack.unpackb(payload, raw=False)
                    
                    # SCENARIO A: IT IS JUST A RENAME
                    if header_file.get("type") == "rename":
                        self.skewer.push(
                            LocalOpcodes.NET_META, 
                            uuid=p_uuid, 
                            local_v_ts=l_v_ts, 
                            remote_v_ts=p_v_ts, 
                            new_virtual_path=header_file["v_path"]
                        )
                        transport.send_message(Opcodes.ACQ_OK)
                        self.skewer.push(LocalOpcodes.LOCAL_MARK_SYNC, uuid=p_uuid, v_ts=p_v_ts)

                    # SCENARIO B: IT IS A FILE TRANSFER HEADER
                    elif header_file.get("type") == "data_header":
                        transport.send_message(Opcodes.ACQ_OK) # Acknowledge the header
                        
                        fd, tmp_path = tempfile.mkstemp(dir=self.dir)
                        transfer_failed = False
                        
                        with open(fd, 'wb') as f:
                            # Safely wait for the exact number of chunks expected
                            for _ in range(header_file["total_chunks"]): 
                                chunk_op, chunk_data = transport.receive_message(timeout=30.0)
                                if chunk_op != Opcodes.VAULT_DATA:
                                    transfer_failed = True
                                    break
                                f.write(chunk_data)
                                transport.send_message(Opcodes.ACQ_OK)
                                
                        if not transfer_failed:
                            self.skewer.push(
                                LocalOpcodes.NET_DATA,
                                tmp_filepath=tmp_path,
                                virtual_path=header_file["v_path"],
                                uuid=p_uuid,
                                local_v_ts=l_v_ts,
                                remote_v_ts=p_v_ts,
                                created_at=header_file.get("created_at"),
                                hashmap=header_file["hashmap"]
                            )
                            self.skewer.push(LocalOpcodes.LOCAL_MARK_SYNC, uuid=p_uuid, v_ts=p_v_ts)
                        else:
                            transport.send_message(Opcodes.ACQ_FAIL)
                            
                except Exception as e:
                    print(f"[-] Data transfer failed for {p_uuid.hex()[:8]}: {e}")
                    try:
                        transport.send_message(Opcodes.ACQ_FAIL)
                    except Exception:
                        pass
            
            else:
                # Opcode mismatch (e.g. they sent VAULT_DATA without a VAULT_META header)
                transport.send_message(Opcodes.ACQ_FAIL)

        # 4. END OF TURN
        print("[*] Local pull complete. Handing turn over to peer.")
        transport.send_message(Opcodes.SYNC_NUL)

    def _serve_peer_requests(self, transport: SecureNetworkTransport):
        while self.is_running:
            opcode, payload = transport.receive_message(timeout=None)
            
            if opcode in (Opcodes.BYE_GRACE, Opcodes.BYE_FORCE):
                break
                
            elif opcode == Opcodes.SYNC_NUL:
                # The peer is done pulling. Break the loop so we can swap roles.
                break 
                
            elif opcode != Opcodes.SYNC_REQ:
                transport.send_message(Opcodes.SYNC_ERR)
                continue
            
            req_uuid = payload
            
            # Fetch current local state for this UUID
            local_full_ledger = self.ledger.get_ledger()
            l_v_ts = 0
            l_action = None
            
            for record in local_full_ledger:
                if record[0] == req_uuid:  
                    l_v_ts = record[1]    
                    l_action = record[2]   
                    break                  

            if not l_action:
                transport.send_message(Opcodes.SYNC_ERR)
                continue

            try:
                # METADATA UPDATES (Renames)
                if l_action == self.ledger.ACTION_RENAME:
                    meta = self.vault_manager.vaultdb.get_meta(req_uuid, l_v_ts)
                    header_dict = {
                        "type": "rename",
                        "v_path": meta['virtual_path']
                    }
                    transport.send_message(Opcodes.VAULT_META, msgpack.packb(header_dict, use_bin_type=True))
                    
                    # Wait for peer to apply metadata
                    transport.receive_message(timeout=10.0) 

                #FULL FILE UPDATES (Edits / Ingests)
                elif l_action in (self.ledger.ACTION_EDIT, self.ledger.ACTION_INGEST):
                    meta = self.vault_manager.vaultdb.get_meta(req_uuid, l_v_ts)
                    original_chunks = self.vault_manager.hashmap.get_meta(req_uuid, l_v_ts)
                    
                    if not original_chunks:
                        transport.send_message(Opcodes.SYNC_ERR)
                        continue

                    # Normalize Hashmap (Zero-based offset)
                    base_offset = original_chunks[0]['start']
                    normalized_hashmap = [{"iv": c["iv"] ,"start": c["start"] - base_offset, "end": c["end"] - base_offset} for c in original_chunks]

                    # 1. Send the MsgPack Header
                    header_dict = {
                        "type": "data_header",
                        "v_path": meta['virtual_path'],
                        "created_at": meta['created_at'],
                        "total_chunks": len(original_chunks),
                        "hashmap": normalized_hashmap
                    }
                    header_payload = msgpack.packb(header_dict, use_bin_type=True)
                    transport.send_message(Opcodes.VAULT_META, header_payload)
                    
                    ack, _ = transport.receive_message(timeout=10.0)
                    if ack != Opcodes.ACQ_OK:
                        continue 
                        
                    # 2. Stream the encrypted chunks one by one
                    transfer_failed = False

                    for chunk in original_chunks:
                        # Read raw bytes using exact disk offsets
                        with self.vault_manager.io_lock:
                            enc_bytes = self.vault_manager.vaultio.read_cargo(chunk['start'], chunk['end'])
                        transport.send_message(Opcodes.VAULT_DATA, enc_bytes)
                        
                        # Await flow-control ACQ_OK
                        chunk_ack, _ = transport.receive_message(timeout=10.0)
                        if chunk_ack != Opcodes.ACQ_OK:
                            transfer_failed = True
                            break 
                                
                    if transfer_failed:
                        print(f"[-] Peer aborted chunk transfer for {req_uuid.hex()[:8]}")
                        
                else:
                    # If it's a DELETE, the peer shouldn't be asking for it!
                    transport.send_message(Opcodes.SYNC_ERR)
                    
            except Exception as e:
                print(f"[-] Error serving request for {req_uuid.hex()[:8]}: {e}")
                transport.send_message(Opcodes.SYNC_ERR)
                