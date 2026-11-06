from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceListener
import socket
from modules.crypto_core import hashing
import time

SYNC_SERVICE = "_monolog-sync._tcp.local."
PAIR_SERVICE = "_monolog-pair._tcp.local."

class DesktopDiscover(ServiceListener):
    def __init__(self):
        self.zc = Zeroconf()
        self.discovered_vaults = {}
        self.sync_info = None
        self.pair_info = None
        
        # We now keep one permanent browser alive instead of recreating it
        self.browser = None
        
        self.my_port = None
        self.mdns_safe_hash_str = None
        self.device_name = socket.gethostname()
    
    @staticmethod
    def get_local_ipv4():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))  
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1' 
        finally:
            s.close()
        return ip

    def broadcast_presence(self, dsa_pub_key: bytes, port: int = 65432):
        self.set_identity(dsa_pub_key, port)
        self.start_sync_beacon()
    
    def set_identity(self, dsa_pub_key: bytes, port: int = 65432):
        self.my_port = port
        raw_hash = hashing.hash_key(dsa_pub_key)
        self.mdns_safe_hash_str = hashing.hash_convert_str(raw_hash)

    def _create_service_info(self, service_type: str) -> ServiceInfo:
        broadcaster_device = f"{self.device_name}-{self.my_port}"
        local_ip = self.get_local_ipv4()
        
        return ServiceInfo(
            type_ = service_type,
            name = f"{broadcaster_device}.{service_type}",
            addresses = [socket.inet_aton(local_ip)],
            port = self.my_port,
            properties = {b"ML-DSA-HASH" : self.mdns_safe_hash_str.encode('utf-8')}, 
            server = f"{broadcaster_device}.local."
        )

    # ==================== BEACON CONTROLS ====================
    def start_sync_beacon(self):
        if not self.sync_info and self.my_port:
            self.sync_info = self._create_service_info(SYNC_SERVICE)
            self.zc.register_service(self.sync_info)
            
            # Start the permanent background scanner as soon as the beacon goes live
            if not self.browser:
                self.browser = ServiceBrowser(self.zc, [SYNC_SERVICE, PAIR_SERVICE], self)

    def stop_sync_beacon(self):
        if self.sync_info:
            self.zc.unregister_service(self.sync_info)
            self.sync_info = None

    def start_pairing_beacon(self):
        if not self.pair_info and self.my_port:
            self.pair_info = self._create_service_info(PAIR_SERVICE)
            self.zc.register_service(self.pair_info)

        if not self.browser:
            self.browser = ServiceBrowser(
                self.zc,
                [SYNC_SERVICE, PAIR_SERVICE],
                self
            )

    def stop_pairing_beacon(self):
        if not self.pair_info and self.my_port:
            self.pair_info = self._create_service_info(PAIR_SERVICE)
            self.zc.register_service(self.pair_info)

    # ==================== SCANNING & ROUTING ====================
    def scan_for_devices(self, scan_time_seconds=5, mode="SYNC"):
        if not self.browser:
            self.browser = ServiceBrowser(
                self.zc,
                [SYNC_SERVICE, PAIR_SERVICE],
                self
            )
        if scan_time_seconds > 0:
            time.sleep(scan_time_seconds)
            
        filtered_vaults = {}
        for name, data in self.discovered_vaults.items():
            if mode == "SYNC" and data.get("mode") != "SYNC":
                continue
            if mode == "PAIR" and data.get("mode") != "PAIR":
                continue
            filtered_vaults[name] = data
            
        return filtered_vaults
    
    def add_service(self, zc, type_, name):


        info = zc.get_service_info(type_, name)

        if not info:
            return

        discovered_ip = socket.inet_ntoa(info.addresses[0])

        if discovered_ip == self.get_local_ipv4() and info.port == self.my_port:
            return

        hash_bytes = info.properties.get(b"ML-DSA-HASH", b"")
        extracted_hash_str = hash_bytes.decode("utf-8") if hash_bytes else ""

        beacon_mode = "PAIR" if "pair" in type_.lower() else "SYNC"

        self.discovered_vaults[name] = {
            "ip": discovered_ip,
            "port": info.port,
            "ML-DSA-HASH": extracted_hash_str,
            "mode": beacon_mode
        }
    
    def update_service(self, zc, type_, name):
        # Zeroconf calls this if a property changes; we just re-add it to update the dict
        self.add_service(zc, type_, name)
    
    def remove_service(self, zc, type_, name):
        if name in self.discovered_vaults:
            del self.discovered_vaults[name]
    
    def cleanup(self):
        if self.browser:
            try:
                self.browser.cancel()
            except Exception:
                pass
            self.browser = None
            
        self.stop_sync_beacon()
        self.stop_pairing_beacon()
        
        try:
            self.zc.close()
        except Exception:
            pass