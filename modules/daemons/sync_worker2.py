import os 
import socket
import subprocess
import concurrent.futures
import tempfile
import platform
import threading
import json
import time

from modules.system import SecureNetworkTransport, PrivateKeyManager, TrustedDevicesDatabase, Opcodes
from modules.network import DesktopDiscover
from modules.crypto_core import hashing, SasPass

class SecurityError(Exception):
    pass

class SyncWorker:
    def __init__(self, port: int = 65432, storage_dir=None):
        self.port = port 
        self.dir = storage_dir if storage_dir else tempfile.gettempdir()
        
        #identity
        self.pvt_key_mgr = PrivateKeyManager()
        self.my_identity = self.pvt_key_mgr.get_or_create_identity()
        self.peers = TrustedDevicesDatabase(self.dir)
        
        #network classes
        self.discovery = DesktopDiscover()
        
        #device info
        self.local_name, self.local_type = self.get_device_identity()
        self.is_running = False 
        self.server_socket = None
        self._listener = None 
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(5)
        
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
            identity = self.pvt_key_mgr.get_or_create_identity()
            dsa_pub_key = identity.generate_key("pub")
            self.discovery.broadcast_presence(dsa_pub_key)

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
                #send to syncing HERE
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
        pub_hash = hashing.hash_key(self.my_identity.generate_key("pub"))
        
        is_known = self.peers.is_device_trusted(expected_mdns_hash)

        #==========Routing Protocol=======================
        if is_known:
            transport.send_message(Opcodes.TRUST_QRY, pub_hash)
            opcode, _ = transport.receive_message()
            if opcode == Opcodes.TRUST_YES:
                pass
                #Send to syncing
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
            peer_key = self._opcode_check(transport.receive_message(), Opcodes.DSA_PUB, transport, Opcodes.PUB_ERR)
            self_key = self.my_identity.generate_key("pub")
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
            sas_pin = input(f"Enter the 6-digit PIN displayed on Bob's screen: ").strip()
            
            if hashing.verify_pass(sas_pin, self_key, peer_key):
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
            self_key = self.my_identity.generate_key("pub")
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
            print(f"\n======================================")
            print(f"     SECUREVAULT PAIRING PIN          ")
            print(f"     PIN: {PIN}                       ")
            print(f"======================================\n")
            
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