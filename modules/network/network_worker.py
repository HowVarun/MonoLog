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
import random
import struct

from modules.system import Opcodes, LocalOpcodes
from modules.network import DesktopDiscover, SecureNetworkTransport, TrustedDevicesDatabase
from modules.system import PrivateKeyManager
from modules.crypto_core import hashing, SasPass, AesGcm, MLKEM


class SecurityError(Exception):
    pass

class NetworkWorker:
    def __init__(self, vault_manager ,port: int = 65432, storage_dir=None):
        #debugging and testing simultaneous machine operation
        node_id = int(os.getenv("SV_NODE", "1"))
        self.port = port + (node_id -1)
        if node_id > 1:
            default_dir = os.path.join(tempfile.gettempdir(), f"sv_node_{node_id}")
            os.makedirs(default_dir, exist_ok=True)
        else:
            default_dir = tempfile.gettempdir()

        self.dir = storage_dir if storage_dir else default_dir
        self.vault_manager = vault_manager
        self.skewer = getattr(self.vault_manager, 'skewer', None)

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

        #Sync lock and pairing lock
        self.sync_lock = threading.Lock()
        self.pairing_mode = False

        #Vault clone setup
        self.ui_new_vault_creds_cb = None  # Returns (new_master_password, new_weak_pin)

        
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

    @property
    def vault_id(self) -> bytes:
        # Return a static placeholder if no vault is unlocked yet during clone/import
        if not self.vault_manager or not getattr(self.vault_manager, 'dek', None):
            return b"PRE_VAULT_SETUP_123456789012"
            
        digest = hashing.hash_key(b"MONOLOG_VAULT_ID:" + bytes(self.vault_manager.dek))
        return b"SCAF" + digest[:28]

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

    def enable_pairing_mode(self):
        #Turns on pairing mode in discovery
        self.pairing_mode = True
        self.discovery.set_identity(self.my_pub_key, self.port)
        self.discovery.stop_sync_beacon()
        self.discovery.start_pairing_beacon()
        print("[*] Pairing Mode ENABLED. Vault is visible to new devices.")

    def disable_pairing_mode(self):
        self.pairing_mode = False
        self.discovery.stop_pairing_beacon()
        
        if self.is_running:
            self.discovery.start_sync_beacon()
            print("[*] Pairing Mode DISABLED. Background mesh resumed.")
        else:
            print("[*] Pairing Mode DISABLED. (Worker is shutting down, sync beacon remains off).")
    

    #==========================================================
    #Helper functions
    def _opcode_check(self, received_msg: tuple, expected_opcode: bytes, transport: SecureNetworkTransport, fail_opcode: bytes = Opcodes.BYE_FORCE) -> bytes:
        opcode_recv, payload = received_msg
        
        if opcode_recv == expected_opcode:
            return payload
        elif opcode_recv == Opcodes.BYE_FORCE:
            transport.close_connection()
            raise ConnectionError("Peer has forcefully disconnected connection")
            
        # If they send the wrong thing, send the fail opcode (Defaults to BYE_FORCE)
        transport.send_message(fail_opcode)
        raise ValueError(f"Protocol Violation: Expected {expected_opcode}, got {opcode_recv}")
         
    
    def _verify_rcvd(self, transport : SecureNetworkTransport):
        transport.send_message(Opcodes.ACQ_OK)
    
    def _verify_sent(self, transport : SecureNetworkTransport):
        opcode, _ = transport.receive_message()
        if opcode == Opcodes.ACQ_OK:
            return True
        else:
            transport.send_message(Opcodes.ACQ_FAIL)
    def _generate_vault_proof(self) -> bytes:
            if not self.vault_manager or not getattr(self.vault_manager, 'dek', None):
                return b""
            iv, ct = AesGcm(self.vault_manager.dek).encrypt_cipherstream(self.vault_id)
            return iv + ct
    
    def _verify_vault_proof(self, proof_bytes: bytes) -> bool:
        try:
            iv, ct = proof_bytes[:12], proof_bytes[12:]
            pt = AesGcm(self.vault_manager.dek).decrypt_cipherstream(iv, ct)
            return pt == self.vault_id and pt.startswith(b"SCAF")
        except Exception:
            return False

    def _check_partner_slot(self, peer_hash: bytes, transport: SecureNetworkTransport = None):
        if self.vault_id.startswith(b"PRE_VAULT"):
            return
        peers = self.peers.get_vault_peers(self.vault_id)
        active_hashes = [peer["ml_dsa_hash"] for peer in peers]
        if len(active_hashes) >= 5 and peer_hash not in active_hashes:
            if transport:
                transport.send_message(Opcodes.PAIR_FULL)
            raise SecurityError("Vault has reached the maximum limit of 5 paired devices!")
        

    def _resolve_name_collision(self, base_name: str) -> str:
        
        existing_names = []
        for p in self.peers.get_all_peers():
            name = p.get('nickname') or p.get('device_name') or ""
            existing_names.append(name.lower())
            
        existing_names.append((self.local_name or "").lower())
        
        safe_base = (base_name or "Unknown Device")
        if safe_base.lower() not in existing_names:
            return safe_base
            
        counter = 1
        while f"{safe_base} ({counter})".lower() in existing_names:
            counter += 1
        return f"{safe_base} ({counter})"

    def _sync_file_stream(self, transport: SecureNetworkTransport, total_chunks: int):
        #generator yields incoming file chunks from the network
        for _ in range(total_chunks):
            opcode, chunk_data = transport.receive_message(timeout=30.0)
            if opcode != Opcodes.VAULT_DATA or not chunk_data:
                raise ConnectionError(f"Expected VAULT_DATA during stream, got {opcode}")
            
            # Update progress immediately after receiving
            if hasattr(self, 'vault_manager') and self.vault_manager.progress.active:
                self.vault_manager.progress.add_bytes(len(chunk_data))
                
            yield chunk_data

        # Sent only after VaultIO.write_cargo has written every yielded chunk to .temp
        transport.send_message(Opcodes.ACQ_OK)

    def _transit_stream(self, transport: SecureNetworkTransport, file_size: int):
        received_bytes = 0
        
        # Start the UI progress bar!
        if hasattr(self.vault_manager, 'progress'):
            self.vault_manager.progress.start_transfer("Vault Clone", file_size, "Downloading")
            
        try:
            while received_bytes < file_size:
                chunk = self._opcode_check(transport.receive_message(timeout=30.0), Opcodes.VAULT_DATA, transport)
                received_bytes += len(chunk)
                
                # Update the UI
                if hasattr(self.vault_manager, 'progress'):
                    self.vault_manager.progress.add_bytes(len(chunk))
                    
                yield chunk
        finally:
            if hasattr(self.vault_manager, 'progress'):
                self.vault_manager.progress.end_transfer()

    def _verify_dsa(self, peer_pub_key: bytes, expected_message: bytes, signature: bytes) -> bool:
        try:
            return self.my_identity.verify(expected_message, signature, peer_pub_key)
        except Exception:
            return False

    #==========================================================
    def start(self):
        if self.is_running:
            return False
        else:
            self.peers.create_db()
            self.discovery.broadcast_presence(self.my_pub_key, self.port)

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
    def _inbound_router(self, transport: SecureNetworkTransport):
        opcode_received, payload = transport.receive_message()
        if opcode_received == Opcodes.NUKE_WIPE:
            self._handle_nuclear_wipe(payload)
            return

        if opcode_received == Opcodes.TRUST_QRY:
            peer_hash, client_nonce = msgpack.unpackb(payload, raw=False)
        else:
            peer_hash, client_nonce = payload, None

        if self.peers.check_if_compromised(peer_hash):
            wipe_payload = b"WIPE:" + peer_hash
            sig = self.my_identity.sign(wipe_payload)
            transport.send_message(Opcodes.NUKE_WIPE, msgpack.packb([self.my_pub_key, sig], use_bin_type=True))
            return

        # ============== PROTOCOL ROUTING ==============
        if opcode_received == Opcodes.TRUST_QRY:  # Phase 1: Trust Verification
            peer_data = self.peers.is_device_trusted(peer_hash, self.vault_id)

            if peer_data:
                if peer_data.get('is_paused') == 1:
                    transport.send_message(Opcodes.SYNC_ERR)
                    return
                #phase1 : generate the ml-kem keypair then sign and send
                server_nonce = os.urandom(32)
                temp_mlkem = MLKEM()
                kem_pub_server = temp_mlkem.generate_key("pub")
                #signing and sending
                expected_msg = client_nonce + server_nonce + kem_pub_server
                server_sig = self.my_identity.sign(expected_msg)
                transport.send_message(
                    Opcodes.TRUST_YES,
                    msgpack.packb([server_sig, server_nonce, kem_pub_server], use_bin_type=True)
                )

                #phase2: sync request & client signature verification
                next_op, payload = transport.receive_message()
                if next_op == Opcodes.SYNC_QRY:
                    client_sig, ciph2 = msgpack.unpackb(payload, raw = False)
                    if not self._verify_dsa(peer_data['ml_dsa_pub_key'], server_nonce + ciph2, client_sig):
                        transport.send_message(Opcodes.SYNC_ERR)
                        raise SecurityError("Client failed ML-DSA-87 challenge verification")

                    try:
                        session_key = temp_mlkem.decapsulate(ciph2)
                    except Exception as e:
                        raise SecurityError("Client did not send valid ML-KEM key")

                    transport.send_message(Opcodes.SYNC_YES)
                    transport.enable_tunnel_encryption(session_key)
                    self._execute_sync_session(transport, peer_hash, is_client=False)
                else:
                    transport.send_message(Opcodes.SYNC_ERR)
                    raise SecurityError(f"Expected SYNC_QRY, got {next_op}")
            else:
                transport.send_message(Opcodes.DEVC_RM, self.my_identity.sign(client_nonce))
                raise SecurityError("Peer requested verification but device is not trusted")

        elif opcode_received == Opcodes.DSA_HASH:  # Attempts pairing
            peer_data = self.peers.is_device_trusted(peer_hash, self.vault_id)

            if not peer_data:
                if not self.pairing_mode:
                    transport.send_message(Opcodes.SYNC_ERR)
                    return
                
                self._check_partner_slot(peer_hash, transport)
                transport.send_message(Opcodes.TRUST_NO)
                self._execute_pairing_server(transport, peer_hash)
            elif peer_data:
                server_nonce = os.urandom(32)
                transport.send_message(Opcodes.TRUST_YES, server_nonce)
                recv_op, rm_sig = transport.receive_message()
                if recv_op == Opcodes.DEVC_RM and self._verify_dsa(peer_data['ml_dsa_pub_key'], server_nonce, rm_sig):
                    self.peers.remove_peer(peer_hash, self.vault_id)
                    transport.send_message(Opcodes.TRUST_RM)
                else:
                    raise SecurityError("Invalid or spoofed DEVC_RM response")
            else:
                raise SecurityError("Trusted Devices database compromised")
        else:
            raise ValueError("Did not receive a valid routing opcode")

    def _route_inbound_connection(self, client_sock: socket.socket, addr: tuple):
        transport = SecureNetworkTransport(sock=client_sock)
        if not self.sync_lock.acquire(blocking=False):
            print(f"[*] Busy: Rejected inbound connection from {addr[0]}.")
            try:
                transport.send_message(Opcodes.BYE_FORCE)
            except Exception:
                pass  
            client_sock.close()
            return
        try:
            ping_bytes = self._opcode_check(transport.receive_message(), Opcodes.PING, transport)
            transport.send_message(Opcodes.PONG, ping_bytes)
            self._inbound_router(transport)

        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure with {addr[0]}: {e}")
        finally:
            transport.close_connection()
            self.sync_lock.release()
            
    #===========================================================================================================================
    def _outbound_router(self, transport: SecureNetworkTransport, expected_mdns_hash: bytes):
        pub_hash = hashing.hash_key(self.my_pub_key)

        if self.peers.check_if_compromised(expected_mdns_hash):
            wipe_payload = b"WIPE:" + expected_mdns_hash
            sig = self.my_identity.sign(wipe_payload)
            transport.send_message(Opcodes.NUKE_WIPE, msgpack.packb([self.my_pub_key, sig], use_bin_type=True))
            return "WIPED_PEER"

        is_known = self.peers.is_device_trusted(expected_mdns_hash, self.vault_id)

        # ========== Routing Protocol ==========
        if is_known:
            if is_known.get('is_paused') == 1:
                print("[*] Sync is paused for this device.")
                return "PAUSED"

            # Phase 1: Verify Trust
            client_nonce = os.urandom(32)
            transport.send_message(
                Opcodes.TRUST_QRY,
                msgpack.packb([pub_hash, client_nonce], use_bin_type=True)
            )
            opcode, payload = transport.receive_message()

            if opcode == Opcodes.NUKE_WIPE:
                self._handle_nuclear_wipe(payload, expected_mdns_hash)
                return "SELF_WIPED"

            if opcode == Opcodes.SYNC_ERR:
                print("[*] Peer is not accepting pairing requests right now.")
                return "PAIR_REJECTED"
            

            if opcode == Opcodes.TRUST_YES:
                server_sig, server_nonce, kem_pub_server = msgpack.unpackb(payload, raw=False)
                expected_msg = client_nonce + server_nonce + kem_pub_server

                if not self._verify_dsa(is_known['ml_dsa_pub_key'], expected_msg, server_sig):
                    raise SecurityError("Server failed ML-DSA-87 challenge verification!")
                
                temp_mlkem = MLKEM()
                kem_pub_client = temp_mlkem.generate_key("pub")
                ciph, session_key = temp_mlkem.encapsulate(kem_pub_server)

                client_sig = self.my_identity.sign(server_nonce + ciph)

                # Phase 2: Request Sync with signed server_nonce
                transport.send_message(
                    Opcodes.SYNC_QRY,
                    msgpack.packb([client_sig, ciph], use_bin_type = True ))
                
                sync_op, _ = transport.receive_message()

                if sync_op == Opcodes.SYNC_YES:
                    transport.enable_tunnel_encryption(session_key)
                    self._execute_sync_session(transport, expected_mdns_hash, is_client=True)
                    return "SYNC_OK"
                elif sync_op == Opcodes.SYNC_ERR:
                    print("[*] Peer rejected sync (paused or busy).")
                    return "PAUSED"
                else:
                    raise SecurityError(f"Unexpected response to SYNC_QRY: {sync_op}")

            elif opcode == Opcodes.DEVC_RM:
                if not self._verify_dsa(is_known['ml_dsa_pub_key'], client_nonce, signature = payload):
                    raise SecurityError("Spoofed DEVC_RM rejected!")
                self.peers.remove_peer(expected_mdns_hash, self.vault_id)
                transport.send_message(Opcodes.TRUST_RM)
                return "UNPAIRED_BY_PEER"
            else:
                raise SecurityError(f"Invalid opcode at current stage: {opcode}")

        else:
            self._check_partner_slot(expected_mdns_hash)
            transport.send_message(Opcodes.DSA_HASH, pub_hash)
            opcode, payload = transport.receive_message()

            if opcode == Opcodes.NUKE_WIPE:
                self._handle_nuclear_wipe(payload, expected_mdns_hash)
                return "SELF_WIPED"

            if opcode == Opcodes.TRUST_NO:
                self._execute_pairing_client(transport, expected_mdns_hash)
                return "PAIRED_OK"
            elif opcode == Opcodes.TRUST_YES:
                transport.send_message(Opcodes.DEVC_RM, self.my_identity.sign(payload))
                opcode, _ = transport.receive_message()
                if opcode == Opcodes.TRUST_RM:
                    return "UNPAIRED_BY_PEER"
                else:
                    raise SecurityError("Secondary device not unpaired successfully!")
            elif opcode == Opcodes.PAIR_FULL:
                raise SecurityError("Server vault is already paired with maximum devices!")
            else:
                raise SecurityError(f"Invalid opcode at current stage: {opcode}")
    
    def _route_outbound_connection(self, target_ip: str, target_port: int, expected_mdns_hash: bytes):
        if not self.sync_lock.acquire(blocking=False):
            print("[*] Busy: Sync already in progress.")
            return "BUSY"
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transport = None

        try:
            client_sock.connect((target_ip, target_port))
            transport = SecureNetworkTransport(sock=client_sock)

            rand_byte = os.urandom(8)
            transport.send_message(Opcodes.PING, rand_byte)
            rcvd_byte = self._opcode_check(transport.receive_message(), Opcodes.PONG, transport)
            if rcvd_byte != rand_byte:
                raise SecurityError("Device transport functionality compromised")
            
            return self._outbound_router(transport, expected_mdns_hash)
        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure: {e}")
            return None
        finally:
            if transport:
                transport.close_connection()
            else:
                client_sock.close()
            self.sync_lock.release()

    #===========================================================================================================================
    def _execute_pairing_server(self, transport : SecureNetworkTransport, peer_hash):
        try:
            self_key = self.my_pub_key
            current_vault_id = self.vault_id
            self.ledger = self.vault_manager.ledger

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
                peer_proof_hex = peer_meta.get("vault_proof", "")
                peer_clone = peer_meta.get("wants_clone", False)


                peer_name = self._resolve_name_collision(peer_name)
            except Exception:
                transport.send_message(Opcodes.ID_ERR)
                raise SecurityError("Malformed Metadata payload JSON")

            #if already has a vault then verify it is the correct one
            if not peer_clone:
                if not self._verify_vault_proof(bytes.fromhex(peer_proof_hex)):
                    transport.send_message(Opcodes.ID_ERR)
                    raise SecurityError("Vault Proof Failed! Client has a different vault")
                
            self_devc_meta = {
                "device_name": self.local_name,
                "device_type": self.local_type,
                "app_version": "1.0",
                "vault_proof": self._generate_vault_proof().hex()
            }
            transport.send_message(Opcodes.DEVC_ID, json.dumps(self_devc_meta).encode('utf-8'))
            
            # Request Pin out-of-band on Alice's side (To be replaced by UI Thread-Event later)
            sas_pin = self._request_pin(peer_name)
            
            if SasPass.verify_pass(sas_pin, self_key, peer_key):
                transport.send_message(Opcodes.AUTH_PASS)
                
                opcode, _ = transport.receive_message()
                if opcode == Opcodes.AUTH_PASS:

                    #ML-KEM CLONE TRANSFERRINGGGG
                    if peer_clone:
                        peer_kem_pub = self._opcode_check(transport.receive_message(), Opcodes.KEM_PUB, transport)
                        kem = MLKEM()
                        kem_ciph, shared_secret = kem.encapsulate(peer_kem_pub)
                        transport.send_message(Opcodes.KEM_CIPH, kem_ciph)
                        from modules.orchestrator import VaultDynamicManager
                        surgeon = VaultDynamicManager(self.vault_manager)
                        transit_path = surgeon.prepare_vault_transfer(shared_secret)
                        
                        # 1. Send Encrypted Ledger
                        local_unsynced = self.ledger.get_unsynced_payload()
                        ldg_pt = msgpack.packb(local_unsynced, use_bin_type=True)
                        kem_aes = AesGcm(shared_secret)
                        ldg_iv, ldg_ct = kem_aes.encrypt_cipherstream(ldg_pt)
                        transport.send_message(Opcodes.SYNC_LDG, ldg_iv + ldg_ct)
                        self._opcode_check(transport.receive_message(timeout=10.0), Opcodes.ACQ_OK, transport)
                        
                        # 2. Send Vault Size
                        file_size = os.path.getsize(transit_path)
                        transport.send_message(Opcodes.VAULT_FULL, struct.pack(">Q", file_size))
                        self._opcode_check(transport.receive_message(timeout=10.0), Opcodes.ACQ_OK, transport)
                        
                        # 3. Stream the Vault
                        for chunk in surgeon.stream_transit_vault(transit_path):
                            transport.send_message(Opcodes.VAULT_DATA, chunk)
                            
                        self._opcode_check(transport.receive_message(timeout=30.0), Opcodes.ACQ_OK, transport)
                            
                        os.remove(transit_path)
                        shared_secret[:] = b'\x00' * 32
                        self.ledger.mark_all_synced(peer_hash)


                    self.peers.add_trusted_device(
                        ml_dsa_hash=peer_hash,
                        vault_id = current_vault_id,
                        device_name=peer_name,
                        device_type=peer_type,
                        ml_dsa_pub_key=peer_key
                    )
                    
                    print(f"\n[+] Vault successfully paired with [{peer_name}]!")
                    
                    if not peer_clone:
                        print("[*] Transitioning to Sync Session...")
                        self._execute_sync_session(transport, peer_hash, is_client=False)
                    else:
                        self.peers.update_last_seen(peer_hash, self.vault_id)
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
            current_vault_id = self.vault_id

            transport.send_message(Opcodes.DSA_PUB, self_key)
            peer_key = self._opcode_check(transport.receive_message(), Opcodes.DSA_PUB, transport, Opcodes.PUB_ERR)

            if not hashing.hash_verify(peer_key, peer_hash):
                transport.send_message(Opcodes.HASH_ERR)
                raise SecurityError("Hash does not match key!")

            active_files = self.vault_manager.vaultdb.get_active_files() if getattr(self.vault_manager, 'vaultdb', None) else []
            wants_clone = self.vault_id.startswith(b"PRE_VAULT")

            self_devc_meta = {
                "device_name": self.local_name,
                "device_type": self.local_type,
                "app_version": "1.0",
                "vault_proof": self._generate_vault_proof().hex(),
                "wants_clone": wants_clone
            }
            transport.send_message(Opcodes.DEVC_ID, json.dumps(self_devc_meta).encode('utf-8'))
            
            peer_devc_meta_bytes = self._opcode_check(transport.receive_message(), Opcodes.DEVC_ID, transport, Opcodes.ID_ERR)
            
            try:
                peer_meta = json.loads(peer_devc_meta_bytes.decode('utf-8'))
                peer_name = peer_meta.get("device_name", "Unknown Device")
                peer_type = peer_meta.get("device_type", "Unknown OS")
                peer_proof_hex = peer_meta.get("vault_proof", "")

                peer_name = self._resolve_name_collision(peer_name)
            except Exception:
                transport.send_message(Opcodes.ID_ERR)
                raise SecurityError("Malformed Metadata payload JSON")
            

            # Verify Server holds the exact same unlocked .scaf DEK
            if not wants_clone:
                if not self._verify_vault_proof(bytes.fromhex(peer_proof_hex)):
                    transport.send_message(Opcodes.ID_ERR)
                    raise SecurityError("Vault Proof Failed! Server has a different vault unlocked.")
            
            PIN = SasPass.derive_pass(peer_key, self_key)
            self._display_pin(peer_name, PIN)
            
            opcode, _ = transport.receive_message(timeout=60.0) # Allow up to 1 minute for Alice's input
            
            if opcode == Opcodes.AUTH_PASS:
                transport.send_message(Opcodes.AUTH_PASS)

                #MLKEM VAULT TRAANSFERRR
                if wants_clone:
                    kem = MLKEM()
                    kem_pub = kem.generate_key("pub")
                    transport.send_message(Opcodes.KEM_PUB, kem_pub)

                    kem_ciph = self._opcode_check(transport.receive_message(), Opcodes.KEM_CIPH, transport, Opcodes.CIPH_ERR)
                    shared_secret = kem.decapsulate(kem_ciph)

                    #1. Recieve syncldg
                    peer_ldg_payload = self._opcode_check(transport.receive_message(10.0), Opcodes.SYNC_LDG, transport, Opcodes.SYNC_ERR)
                    transport.send_message(Opcodes.ACQ_OK)

                    kem_aes = AesGcm(shared_secret)
                    ldg_iv, ldg_ct = peer_ldg_payload[:12], peer_ldg_payload[12:]
                    ldg_pt = kem_aes.decrypt_cipherstream(ldg_iv, ldg_ct)
                    peer_unsynced_data = msgpack.unpackb(ldg_pt, raw=False, strict_map_key=False)
                    
                    # 2. Receive File Size
                    file_size_bytes = self._opcode_check(transport.receive_message(timeout=10.0), Opcodes.VAULT_FULL, transport)
                    file_size = struct.unpack(">Q", file_size_bytes)[0]
                    transport.send_message(Opcodes.ACQ_OK)

                    received_tmp_path = os.path.join(self.dir, f"received_{peer_name.replace(' ', '_')}.tmp")
                    
                    print(f"[*] Downloading {file_size / (1024*1024):.1f} MB Vault from {peer_name}...")
                    
                    # 3. Delegate the raw disk write to the Surgeon using our generator!
                    from modules.orchestrator import VaultDynamicManager
                    surgeon = VaultDynamicManager(self.vault_manager)
                    surgeon.receive_transit_vault(
                        received_tmp_path, 
                        self._transit_stream(transport, file_size)
                    )
                    transport.send_message(Opcodes.ACQ_OK)
                    transport.send_message(Opcodes.BYE_GRACE)

                    print("\n" + "="*38)
                    print(" 🎉 VAULT DOWNLOAD COMPLETE")
                    print("="*38)

                    if self.ui_new_vault_creds_cb:
                        new_mp, new_wp = self.ui_new_vault_creds_cb()
                    else:
                        new_mp = input(f"[?] Set Master Password for this cloned vault: ")
                        new_wp = input(f"[?] Set 4-Digit PIN for this cloned vault: ")
                    
                    final_dest = self.vault_manager.filepath
                    
                    # Surgeon re-wraps the DEK and flips the header to .SCAF
                    surgeon.process_received_vault(received_tmp_path, final_dest, shared_secret, new_mp, new_wp)
                    shared_secret[:] = b'\x00' * 32

                    
                    self.vault_manager.unlock_hash(new_mp, new_wp)
                    self.vault_manager.boot_vault()
                    self.ledger = self.vault_manager.ledger
                    self.skewer = getattr(self.vault_manager, 'skewer', None)
                    current_vault_id = self.vault_id

                    if self.vault_manager.ledger:
                        self.vault_manager.ledger.ledger = peer_unsynced_data
                        self.vault_manager.ledger._flush()

                    self.peers.add_trusted_device(
                      ml_dsa_hash=peer_hash,
                      vault_id=current_vault_id,
                      device_name=peer_name,
                      device_type=peer_type,
                      ml_dsa_pub_key=peer_key
                    )
                    self.peers.update_last_seen(peer_hash, current_vault_id)
                    
                    print("[+] Vault decrypted and ready for UI Boot!")

                    
                else:
                    # NOT CLONING: Re-Pairing an existing vault. 
                    # Transition seamlessly into syncing to fix each other's vaults!
                    self.peers.add_trusted_device(
                      ml_dsa_hash=peer_hash,
                      vault_id=current_vault_id,
                      device_name=peer_name,
                      device_type=peer_type,
                      ml_dsa_pub_key=peer_key
                    )
                    print("[*] Re-pairing successful. Transitioning directly to Sync Session...")
                    self._execute_sync_session(transport, peer_hash, is_client=True)
                     # execute_sync_session handles BYE_GRACE

                self.peers.add_trusted_device(
                    ml_dsa_hash=peer_hash,
                    vault_id = current_vault_id,
                    device_name=peer_name,
                    device_type=peer_type,
                    ml_dsa_pub_key=peer_key
                )
                self.peers.update_last_seen(peer_hash, current_vault_id)
            
            elif opcode == Opcodes.AUTH_FAIL:
                raise SecurityError("ENTERED WRONG SAS PIN")

        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Pairing failure: {e}")

    #===========================================================================================================================
    def _execute_sync_session(self, transport: SecureNetworkTransport, peer_hash: str, is_client: bool):
        if not self.vault_manager or not getattr(self.vault_manager, 'ledger', None):
            transport.send_message(Opcodes.BYE_FORCE)
            return

        self.ledger = self.vault_manager.ledger
        self.skewer = self.vault_manager.skewer

        try:
            # 1. Strict Linear Handshake
            if is_client:
                transport.send_message(Opcodes.SYNCO, self._generate_vault_proof())
                peer_proof = self._opcode_check(transport.receive_message(), Opcodes.ACQ_OK, transport)
                if not self._verify_vault_proof(peer_proof):
                    raise SecurityError("Vault Proof Failed! Peer has a different vault open.")
            else:
                peer_proof = self._opcode_check(transport.receive_message(), Opcodes.SYNCO, transport)
                if not self._verify_vault_proof(peer_proof):
                    transport.send_message(Opcodes.BYE_FORCE)
                    raise SecurityError("Vault Proof Failed! Client has a different vault open.")
                transport.send_message(Opcodes.ACQ_OK, self._generate_vault_proof())

            # 2. Swap Unsynced Ledgers
            sync_aes = AesGcm(self.vault_manager.dek)
            local_unsynced = self.ledger.get_unsynced_payload()
            ldg_pt = msgpack.packb(local_unsynced, use_bin_type=True)
            ldg_iv, ledg_ct = sync_aes.encrypt_cipherstream(ldg_pt)
            local_payload = ldg_iv + ledg_ct
            
            transport.send_message(Opcodes.SYNC_LDG, local_payload)
            rcvd_opcode, peer_payload = transport.receive_message(timeout=15.0)
            
            if rcvd_opcode != Opcodes.SYNC_LDG:
                raise ValueError("Peer failed to provide Sync Ledger")
            peer_ldg_iv, peer_ldg_ct = peer_payload[:12], peer_payload[12:]
            peer_ldg_pt = sync_aes.decrypt_cipherstream(peer_ldg_iv, peer_ldg_ct)
            peer_unsynced_data = msgpack.unpackb(peer_ldg_pt, raw=False, strict_map_key=False)

            # 3. The Turn-Based Sync
            last_seen = self.peers.get_last_seen(peer_hash, self.vault_id)
            if is_client:
                # Client audits and pulls first
                pull_list = self._auditor(peer_unsynced_data, last_seen, is_client)
                self._fetcher(transport, pull_list)
                
                # Client becomes the Server
                self._serve_peer_requests(transport)
            else:
                # Server waits and serves first
                self._serve_peer_requests(transport)
                # Server gets its turn to pull
                pull_list = self._auditor(peer_unsynced_data, last_seen, is_client)
                self._fetcher(transport, pull_list)

            # 4. Graceful Teardown
            if self.skewer:
                self.skewer.task_queue.join()
            self.peers.update_last_seen(peer_hash, self.vault_id)
            transport.send_message(Opcodes.BYE_GRACE)

        except Exception as e:
            print(f"[!] Sync Session Error: {e}")
            try:
                transport.send_message(Opcodes.BYE_FORCE)
            except Exception:
                pass

    def _auditor(self, peer_unsynced_data: dict, last_seen: float, is_client: bool) -> dict:
        local_ledger = self.ledger.get_unsynced_payload() # dict: {uuid: [data_ts, meta_ts, is_del]}
        active_local_files = dict(self.vault_manager.vaultdb.get_active_files()) if hasattr(self.vault_manager, 'vaultdb') else {}
        pull_list = {}
        
        for p_uuid, p_state in peer_unsynced_data.items():
            p_data_ts, p_meta_ts, p_is_del = p_state[0], p_state[1], p_state[2]
            l_state = local_ledger.get(p_uuid, [0, 0, False])
            l_data_ts, l_meta_ts, l_is_del = l_state[0], l_state[1], l_state[2]
            
            # ==========================================================
            # STATE 1: BOTH DELETED (Nothing to do)
            # ==========================================================
            if l_is_del and p_is_del:
                continue

            # ==========================================================
            # STATE 2: PEER DELETED, WE HAVE IT LIVE (Or Never Had It)
            # ==========================================================
            if p_is_del and not l_is_del:
                # Fix Bug 1: If we never had this file locally, ignore the peer's delete tombstone
                if l_meta_ts == 0 or p_uuid not in active_local_files:
                    continue

                peer_del_wins = (p_meta_ts > l_meta_ts) or (p_meta_ts == l_meta_ts and not is_client)
                
                if peer_del_wins:
                    # If we edited the file contents offline since last_seen, save our unseen 
                    # work as a Conflicted Copy before letting the peer's delete kill this UUID!
                    unseen_local_edit = (l_data_ts > last_seen)
                    pull_list[p_uuid] = {
                        "action": self.ledger.ACTION_DELETE,
                        "needs_data": False,
                        "needs_meta": False,
                        "is_fork_loser": unseen_local_edit,
                        "p_data_ts": p_data_ts,
                        "p_meta_ts": p_meta_ts,
                        "l_data_ts": l_data_ts,
                        "l_meta_ts": l_meta_ts,
                        "l_is_del": l_is_del
                    }
                # If our local edit/rename is newer than their delete, we ignore their delete.
                # On the peer's turn (State 3), they will resurrect the file from us.
                continue

            # ==========================================================
            # STATE 3: WE DELETED LOCALLY, PEER HAS IT LIVE (Resurrection)
            # ==========================================================
            if l_is_del and not p_is_del:
                peer_live_wins = (p_meta_ts > l_meta_ts) or (p_meta_ts == l_meta_ts and not is_client)
                
                if peer_live_wins:
                    # Fix Bug 2: Always pull full file (ACTION_EDIT) on resurrection because 
                    # local delete marked is_active = 0 in vaultdb (and VACUUM may have purged chunks).
                    pull_list[p_uuid] = {
                        "action": self.ledger.ACTION_EDIT,
                        "needs_data": True,
                        "needs_meta": True,
                        "is_fork_loser": False,
                        "p_data_ts": p_data_ts,
                        "p_meta_ts": p_meta_ts,
                        "l_data_ts": l_data_ts,
                        "l_meta_ts": l_meta_ts,
                        "l_is_del": l_is_del
                    }
                continue

            # ==========================================================
            # STATE 4: BOTH FILES ARE LIVE (Forks & Asymmetric Sync)
            # ==========================================================
            needs_data = (p_data_ts > l_data_ts) or (p_uuid not in active_local_files)
            needs_meta = (p_meta_ts > l_meta_ts) or (p_meta_ts == l_meta_ts and not is_client and p_meta_ts > last_seen)
            is_fork_loser = False

            # Fix Bug 3: Check if both devices edited the file contents while offline 
            # (and aren't already holding the exact same synced state)
            is_data_fork = (
                (l_data_ts > last_seen) and 
                (p_data_ts > last_seen) and 
                (p_uuid in active_local_files) and
                (p_data_ts != l_data_ts or p_meta_ts != l_meta_ts)
            )
            
            if is_data_fork:
                if p_data_ts > l_data_ts or (p_data_ts == l_data_ts and not is_client):
                    # Peer wins the original UUID. We fork our local file first, then pull theirs.
                    needs_data = True
                    needs_meta = True
                    is_fork_loser = True
                else:
                    # We win the original UUID. Peer will fork theirs and pull from us.
                    continue

            if needs_data:
                derived_action = self.ledger.ACTION_EDIT
            elif needs_meta:
                derived_action = self.ledger.ACTION_RENAME
            else:
                continue

            pull_list[p_uuid] = {
                "action": derived_action,
                "needs_data": needs_data,
                "needs_meta": needs_meta,
                "is_fork_loser": is_fork_loser,
                "p_data_ts": p_data_ts,
                "p_meta_ts": p_meta_ts,
                "l_data_ts": l_data_ts,
                "l_meta_ts": l_meta_ts,
                "l_is_del": l_is_del
            }
            
        return pull_list

    def _fetcher(self, transport: SecureNetworkTransport, pull_list: dict):
        for p_uuid, data in pull_list.items():
            p_action = data["action"]
            needs_data = data["needs_data"]
            needs_meta = data["needs_meta"]
            is_fork_loser = data["is_fork_loser"]
            p_data_ts = data["p_data_ts"]
            p_meta_ts = data["p_meta_ts"]
            l_data_ts = data["l_data_ts"]
            l_meta_ts = data["l_meta_ts"]
            l_is_del = data["l_is_del"]

            # 0. FORK PROTECTION: Save unseen local edit as a Conflicted Copy first
            if is_fork_loser and not l_is_del and l_meta_ts > 0:
                self.skewer.push(LocalOpcodes.LOCAL_FORK, uuid=p_uuid, active_v_ts=l_meta_ts)

            # 1. DELETIONS (Network Bypass)
            if p_action == self.ledger.ACTION_DELETE:
                self.skewer.push(LocalOpcodes.NET_DEL, uuid=p_uuid, local_v_ts=l_meta_ts, remote_v_ts=p_meta_ts)
                self.skewer.push(
                    LocalOpcodes.LOCAL_MARK_SYNC,
                    uuid=p_uuid, data_ts=p_data_ts, meta_ts=p_meta_ts, is_del=True
                )
                continue

            # 2. REQUEST DATA OR METADATA FROM PEER
            req_opcode = Opcodes.FORCE_FULL if p_action == self.ledger.ACTION_EDIT else Opcodes.REQ_META
            transport.send_message(req_opcode, p_uuid)
            opcode, payload = transport.receive_message(timeout=30.0)

            if opcode in (Opcodes.SYNC_ERR, Opcodes.SYNC_NUL):
                continue  

            # 3. PROCESS INCOMING METADATA AND FILE HEADERS
            if opcode == Opcodes.VAULT_META:
                try:
                    header_file = msgpack.unpackb(payload, raw=False)
                    
                    # SCENARIO A: METADATA RENAME ONLY
                    if header_file.get("type") == "rename":
                        self.skewer.push(
                            LocalOpcodes.NET_META, 
                            uuid=p_uuid, 
                            local_v_ts=l_meta_ts, 
                            remote_v_ts=p_meta_ts, 
                            new_virtual_path=header_file["v_path"]
                        )
                        transport.send_message(Opcodes.ACQ_OK)
                        self.skewer.push(
                            LocalOpcodes.LOCAL_MARK_SYNC,
                            uuid=p_uuid, data_ts=l_data_ts, meta_ts=p_meta_ts, is_del=False
                        )

                    # SCENARIO B: FULL FILE DATA TRANSFER
                    elif header_file.get("type") == "data_header":
                        transport.send_message(Opcodes.ACQ_OK)
                        
                        #1. Calculate total bytes from the incoming hashmap
                        incoming_hashmap = header_file["hashmap"]
                        total_bytes = sum(c["end"] - c["start"] for c in incoming_hashmap)
                        filename = os.path.basename(header_file["v_path"])

                        # 2. Turn on the progress bar before starting the stream
                        self.vault_manager.progress.start_transfer(filename, total_bytes, "Downloading")

                        try:
                            # Delegate temp file streaming to VaultManager (orchestrator)
                            # (No changes to inputs!)
                            tmp_path = self.vault_manager.download_temp_file(
                                self._sync_file_stream(transport, header_file["total_chunks"]), 
                                self.dir
                            )
                        finally:
                            # 3. Turn off the progress bar safely
                            self.vault_manager.progress.end_transfer()

                        # Asymmetric resolution: If we only needed data (our local rename is newer),
                        # preserve our local virtual_path and local meta_ts!
                        if needs_meta or l_is_del or l_meta_ts == 0:
                            target_v_path = header_file["v_path"]
                            final_meta_ts = p_meta_ts
                        else:
                            local_meta = self.vault_manager.vaultdb.get_meta(p_uuid, l_meta_ts)
                            target_v_path = local_meta["virtual_path"] if local_meta else header_file["v_path"]
                            final_meta_ts = l_meta_ts

                        # If file was deleted locally (State 3 resurrection), pass local_v_ts=0
                        active_local_v_ts = 0 if l_is_del else l_meta_ts

                        self.skewer.push(
                            LocalOpcodes.NET_DATA,
                            tmp_filepath=tmp_path,
                            virtual_path=target_v_path,
                            uuid=p_uuid,
                            local_v_ts=active_local_v_ts,
                            remote_v_ts=final_meta_ts,
                            created_at=header_file.get("created_at"),
                            hashmap=header_file["hashmap"]
                        )
                        self.skewer.push(
                            LocalOpcodes.LOCAL_MARK_SYNC,
                            uuid=p_uuid, data_ts=p_data_ts, meta_ts=final_meta_ts, is_del=False
                        )
                except Exception as e:
                    print(f"[-] Data transfer failed for {p_uuid.hex()[:8]}: {e}")
                    try:
                        transport.send_message(Opcodes.ACQ_FAIL)
                    except Exception:
                        pass
            else:
                transport.send_message(Opcodes.ACQ_FAIL)

        # 4. FLUSH DISK QUEUE BEFORE HANDING TURN TO PEER
        if self.skewer:
            self.skewer.task_queue.join()
        # print("[*] Local pull complete. Handing turn over to peer.")
        transport.send_message(Opcodes.SYNC_NUL)


    def _serve_peer_requests(self, transport: SecureNetworkTransport):
        while self.is_running:
            opcode, payload = transport.receive_message(timeout=None)
            
            if opcode in (Opcodes.BYE_GRACE, Opcodes.BYE_FORCE, Opcodes.SYNC_NUL):
                break 
                
            elif opcode not in (Opcodes.FORCE_FULL, Opcodes.REQ_META):
                transport.send_message(Opcodes.SYNC_ERR)
                continue

            req_uuid = payload
            force_full = (opcode == Opcodes.FORCE_FULL)
            l_state = self.ledger.ledger.get(req_uuid)
            if not l_state:
                transport.send_message(Opcodes.SYNC_ERR)
                continue
                
            l_data_ts, l_meta_ts, l_is_del = l_state[0], l_state[1], l_state[2]

            try:
                # 1. RENAME ONLY (Metadata)
                if not force_full and not l_is_del:
                    meta = self.vault_manager.vaultdb.get_meta(req_uuid, l_meta_ts)
                    if not meta:
                        transport.send_message(Opcodes.SYNC_ERR)
                        continue
                    header_dict = {
                        "type": "rename",
                        "v_path": meta['virtual_path']
                    }
                    transport.send_message(Opcodes.VAULT_META, msgpack.packb(header_dict, use_bin_type=True))
                    
                    ack, _ = transport.receive_message(timeout=10.0)
                    if ack != Opcodes.ACQ_OK:
                        print(f"[-] Peer rejected RENAME for {req_uuid.hex()[:8]}")

                # 2. FULL FILE UPDATES (Edits / Ingests / Resurrections)
                elif force_full and not l_is_del:
                    meta = self.vault_manager.vaultdb.get_meta(req_uuid, l_meta_ts)
                    original_chunks = self.vault_manager.hashmap.get_meta(req_uuid, l_meta_ts)
                    
                    if not meta or not original_chunks:
                        transport.send_message(Opcodes.SYNC_ERR)
                        continue

                    base_offset = original_chunks[0]['start']
                    normalized_hashmap = [
                        {"iv": c["iv"], "start": c["start"] - base_offset, "end": c["end"] - base_offset}
                        for c in original_chunks
                    ]

                    header_dict = {
                        "type": "data_header",
                        "v_path": meta['virtual_path'],
                        "created_at": meta['created_at'],
                        "total_chunks": len(original_chunks),
                        "hashmap": normalized_hashmap
                    }
                    transport.send_message(Opcodes.VAULT_META, msgpack.packb(header_dict, use_bin_type=True))
                    
                    ack, _ = transport.receive_message(timeout=10.0)
                    if ack != Opcodes.ACQ_OK:
                        continue 

                    #Progress Bar
                    total_bytes = sum((c['end'] - c['start']) for c in original_chunks)
                    self.vault_manager.progress.start_transfer(meta['virtual_path'], total_bytes, "Uploading")

                    try:
                        for chunk in original_chunks:
                            with self.vault_manager.io_lock:
                                enc_bytes = self.vault_manager.vaultio.read_cargo(chunk['start'], chunk['end'])
                            
                            transport.send_message(Opcodes.VAULT_DATA, enc_bytes)
                            # Update progress immediately after sending
                            self.vault_manager.progress.add_bytes(len(enc_bytes))

                        final_ack, _ = transport.receive_message(timeout=10.0)
                        if final_ack != Opcodes.ACQ_OK:
                            print(f"[-] Peer failed to acknowledge full transfer for {req_uuid.hex()[:8]}")
                    
                    finally:
                        self.vault_manager.progress.end_transfer()
                    
            except Exception as e:
                print(f"[-] Error serving request for {req_uuid.hex()[:8]}: {e}")
                transport.send_message(Opcodes.SYNC_ERR)

    def _handle_nuclear_wipe(self, payload: bytes, peer_hash: bytes = None):
        try:
            unpacker = msgpack.Unpacker(raw=True, strict_map_key=False)
            unpacker.feed(payload)
            unpacked = next(unpacker)
            server_pub_key = bytes(unpacked[0])
            signature = bytes(unpacked[1])

            actual_hash = hashing.hash_key(server_pub_key)

            if peer_hash and actual_hash != peer_hash:
                raise SecurityError("Nuclear Wipe public key does not match peer hash!")

            known_hashes = [p['ml_dsa_hash'] for p in self.peers.get_all_peers()]
            if actual_hash not in known_hashes:
                raise SecurityError("Nuclear Wipe rejected: unknown device!")

            expected_msg = b"WIPE:" + hashing.hash_key(self.my_pub_key)
            if self._verify_dsa(server_pub_key, expected_msg, signature):
                from modules.orchestrator import VaultDynamicManager
                surgeon = VaultDynamicManager(self.vault_manager)
                surgeon.execute_self_destruct()
            else:
                raise SecurityError("Nuclear Wipe signature invalid!")
        except Exception as e:
            print(f"[-] Ignored invalid Nuclear Wipe command: {e}")