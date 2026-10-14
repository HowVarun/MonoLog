from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceBrowser, ServiceListener
import socket
from modules.crypto_core import hashing
import time


class DesktopDiscover(ServiceListener):
    def __init__(self):
        self.zc = Zeroconf()
        self.discovered_vaults = {}
        self.service_type = "_securevault._tcp.local."
        self.broadcasting_info = None
    
    @staticmethod
    def get_local_ipv4():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))  #Google's DNS IP(any connection outside LAN) 
            ip = s.getsockname()[0]
        except:
            ip = 'ERROR'
        finally:
            s.close()
        return ip
    
    def broadcast_presence(self, dsa_pub_key: bytes, port: int = 65432):
        BROADCASTER_DEVICE = socket.gethostname()
        LOCAL_IP = self.get_local_ipv4()

        # 1. Use the unified hashing module
        raw_hash = hashing.hash_key(dsa_pub_key)
        mdns_safe_hash_str = hashing.hash_convert_str(raw_hash)

        print(f"\n[DEBUG - SERVER] Generating mDNS Hash from Identity Key...")
        print(f"[DEBUG - SERVER] Hash string being broadcasted: {mdns_safe_hash.decode('utf-8')}")
        
        # 2. Bind to self.broadcasting_info so cleanup() works perfectly
        self.broadcasting_info = ServiceInfo(
            type_ = self.service_type,
            name = f"{BROADCASTER_DEVICE}.{self.service_type}",
            addresses = [socket.inet_aton(LOCAL_IP)],
            port = port,
            properties = {b"ML-DSA-HASH" : mdns_safe_hash_str.encode('utf-8')}, 
            server = f"{BROADCASTER_DEVICE}.local."
        )
        
        self.zc.register_service(self.broadcasting_info)
    
    def scan_for_devices(self, scan_time_seconds = 5):
        self.discovered_vaults.clear()
        self.browser = ServiceBrowser(self.zc, self.service_type, self)
        time.sleep(scan_time_seconds)
        self.browser.cancel()
        return self.discovered_vaults
    
    def add_service(self, zc : Zeroconf, type_ : str, name : str):
        info = zc.get_service_info(type_, name)
        if info:
            discovered_ip = socket.inet_ntoa(info.addresses[0])
            
            # FIX 3: Prevent the self-discovery loop! Ignore our own broadcast.
            if discovered_ip == self.get_local_ipv4():
                return
            
            # Extract the hash safely, defaulting to empty string if missing
            hash_bytes = info.properties.get(b"ML-DSA-HASH", b"")
            extracted_hash_str = hash_bytes.decode('utf-8') if hash_bytes else ""
            
            self.discovered_vaults[name] = {
                "ip": discovered_ip,
                "port": info.port,
                "ML-DSA-HASH": extracted_hash_str
            }
    
    def update_service(self, zc, type_, name):
        pass
    
    def remove_service(self, zc, type_, name):
        if name in self.discovered_vaults:
            del self.discovered_vaults[name]
    
    def cleanup(self):
        if self.broadcasting_info:
            self.zc.unregister_service(self.broadcasting_info)
        self.zc.close()

