import os 
import socket
import subprocess
import concurrent.futures
import tempfile
import platform
import threading
import json

from modules.system import SecureNetworkTransport, PrivateKeyManager, TrustedDevicesDatabase, Opcodes
from modules.network import PQCHandshake, DesktopDiscover
from modules.crypto_core import hashing

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
        self.handshake = PQCHandshake(port=self.port)
        
        #device info
        self.local_name, self.local_type = self.get_device_identity()
        self.is_running = False 
        self.server_socket = None
        self._listener = None 
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(5)
        
    
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

    def _opcode_check(self, received_msg: tuple, expected_opcode: bytes, transport: SecureNetworkTransport, fail_opcode: bytes = Opcodes.BYE_FORCE) -> bytes:
        opcode_recv, payload = received_msg
        
        if opcode_recv == expected_opcode:
            return payload
            
        # If they send the wrong thing, send the fail opcode (Defaults to BYE_FORCE)
        transport.send_message(fail_opcode)
        raise ValueError(f"Protocol Violation: Expected {expected_opcode}, got {opcode_recv}")
         
    
    def _verify_rcvd(self, transport : SecureNetworkTransport):
        transport.send_message(Opcodes.ACQ_OK)
    
    def _verify_sent(self, transport : SecureNetworkTransport):
        opcode, _ = transport.receive_message(timeout = 5.0)
        if opcode == Opcodes.ACQ_OK:
            return True
        else:
            transport.send_message(Opcodes.ACQ_FAIL)

    #==========================================================
    
    def start(self):
        if self.is_running:
            return False
        else:
            self.peers.create_db()
            identity = self.pvt_key_mgr.get_or_create_identity()
            _, dsa_pub_key = identity.generate_key()
            _[:] = [0]*len(_) #deleting pvt_key 
            self.discovery.broadcast_presence(dsa_pub_key)

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            
            self._listener = threading.Thread(target=self._network_listener, daemon=True)
            self._listener.start()
    
    def stop(self):
        self.is_running = False
        self.discovery.cleanup()
        self._thread_pool.shutdown(wait=False)
        if self.server_socket:
            self.server_socket.close()
    
    def _network_listener(self):
        while not self.is_running:
            try:
                self.socket.settimeout(1.0)
                client_sock, addr = self.server_socket.accept()
                client_sock.settimeout(None)
                self._thread_pool.submit(self._route_inbound_conn, client_sock, addr)
            except socket.timeout:
                continue
            except Exception:
                if self.is_running:
                    break
    
    #===========================================================================================================================

    def _inbound_router(self, transport : SecureNetworkTransport):

        opcode_received, peer_hash = transport.receive_message(timeout = 5.0)

        #==============PROTOCOL ROUTING===============
        if opcode_received == Opcodes.TRUST_QRY:
            peer_data = self.peers.is_device_trusted(peer_hash)

            if peer_data:
                transport.send_message(Opcodes.TRUST_YES)
                #send to syncing HERE
            else:
                transport.send_message(Opcodes.DEVC_RM)
                #send to pairing(special case)

        elif opcode_received == Opcodes.DSA_HASH:
            peer_data = self.peers.is_device_trusted(peer_hash)

            if not peer_data:
                transport.send_message(Opcodes.TRUST_NO)
                #send to pairing HERE
            elif peer_data:
                transport.send_message(Opcodes.TRUST_YES)
                recv_op, _ = transport.receive_message(timeout = 5.0)
                if recv_op == Opcodes.DEVC_RM:
                    self.peers.remove_peer(peer_hash)
                    transport.send_message(Opcodes.TRUST_RM)
                    #send to pairing HERE
            else:
                raise SecurityError("Trusted Devices database compromised")
        
        elif opcode_received == Opcodes.DEVC_RM:
            self.peers.remove_peer(peer_hash)
            transport.send_message(Opcodes.TRUST_RM)
        else:
            raise ValueError("Did not recieve a valid routing opcode")

    def _route_inbound_connection(self, client_sock: socket.socket, addr: tuple):
        transport = SecureNetworkTransport(sock=client_sock)
        
        try:
            ping_bytes = self._opcode_check(transport.receive_message(timeout=5.0), Opcodes.PING, transport)
            transport.send_message(Opcodes.PONG, ping_bytes)
            self._inbound_router(transport)

            # _, pub_key = self.my_identity.generate_key()
            # _[:] = 0 * len(_)
            # pub_hash = hashing.hash_key(pub_key)
            # transport.send_message(Opcodes.DSA_HASH, pub_hash)  <- Use these methods inside pairing and syncing
        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure with {addr[0]}: {e}")
        finally:
            transport.close_connection()
    #===========================================================================================================================

    def _outbound_router(self, transport : SecureNetworkTransport, expected_mdns_hash : bytes):
        _, pub_key = self.my_identity.generate_key()
        _[:] = 0 * len(_)
        pub_hash = hashing.hash_key(pub_key)
        
        is_known = self.peers.is_device_trusted(expected_mdns_hash)

        #==========Routing Protocol=======================
        if is_known:
            transport.send_message(Opcodes.TRUST_QRY, pub_hash)
            opcode, _ = transport.receive_message(timeout = 5.0)
            if opcode == Opcodes.TRUST_YES:
                pass
                #Send to syncing
            elif opcode == Opcodes.DEVC_RM:
                self.peers.remove_peer(expected_mdns_hash)
                transport.send_message(Opcodes.TRUST_RM)
                #send to pairing (special case)
            else:
                raise SecurityError("Invalid opcode at current stage")
        else:
            transport.send_message(Opcodes.DSA_HASH, pub_hash)
            opcode, _ = transport.receive_message(timeout = 5.0)
            if opcode == Opcodes.TRUST_NO:
                pass #send to pairing
            elif opcode == Opcodes.TRUST_YES:
                transport.send_message(Opcodes.DEVC_RM)
                opcode, _ = transport.receive_message(timeout = 5.0)
                if opcode == Opcodes.TRUST_RM:
                    pass # send to pairing
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
            rcvd_byte = self._opcode_check(transport.receive_message(timeout = 5.0), Opcodes.PONG, transport)
            if rcvd_byte != rand_byte:
                raise SecurityError("Device transport functionality compromised")
            
            self._outbound_router(transport, expected_mdns_hash)
        except Exception as e:
            print(f"[{Opcodes.ERR_FATAL.decode('utf-8')}] Routing failure: {e}")
        finally:
            transport.close_connection()

    #===========================================================================================================================
    
    def _execute_syncing_protocol(self, transport : SecureNetworkTransport, peer_hash : bytes, pub_key : bytes):
        
        peer_pub_key = self._opcode_check(transport.receive_message(timeout = 10.0), Opcodes.DSA_PUB, transport)

        if not hashing.hash_verify(peer_pub_key, peer_hash):
            transport.send_message(Opcodes.HASH_ERR)
            raise ValueError("Public Key does not match the provided hash")

        transport.send_message(Opcodes.DSA_PUB, pub_key)
        

        bob_metadata = self._opcode_check(
            transport.receive_message(timeout = 10.0),
            Opcodes.DEVC_ID,
            transport,
            Opcodes.ID_ERR 
            )
        

        self.peers.add_trusted_device(peer_hash, )
        
        
        
        



            


            

