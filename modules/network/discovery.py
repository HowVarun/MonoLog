from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceBrowser, ServiceListener
import socket
import hashlib
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
    
    def broadcast_presence(self, dsa_pub_key: bytes):
        BROADCASTER_DEVICE = socket.gethostname()


        sha_object = hashlib.sha3_256(dsa_pub_key)
        hash_dsa_pubk = sha_object.hexdigest()

        # --- DEBUG 1: SERVER BROADCAST ---
        print(f"\n[DEBUG - SERVER] Generating mDNS Hash from Identity Key...")
        print(f"[DEBUG - SERVER] Hash string being broadcasted: {hash_dsa_pubk}")
        
        LOCAL_IP = self.get_local_ipv4()
        info = ServiceInfo(
            type_ = self.service_type,
            name = f"{BROADCASTER_DEVICE}.{self.service_type}",
            addresses = [socket.inet_aton(LOCAL_IP)],
            port = 65432,
            properties = {b"ML-DSA-HASH" : hash_dsa_pubk.encode()},
            server = f"{BROADCASTER_DEVICE}.local."
        )
        

        self.zc.register_service(info)
    
    def scan_for_devices(self, scan_time_seconds = 5):
        self.browser = ServiceBrowser(self.zc, self.service_type, self)
        time.sleep(scan_time_seconds)
        self.browser.cancel()
        return self.discovered_vaults
    
    def add_service(self, zc : Zeroconf, type_ : str, name : str):
        info = zc.get_service_info(type_,name)
        if info and info.addresses:
            ip_address = socket.inet_ntoa(info.addresses[0])
            dsa_hash = info.properties.get(b"ML-DSA-HASH", b"").decode()

            self.discovered_vaults[name] = {
                "ip" : ip_address,
                "port" : info.port,
                "ML-DSA-HASH" : dsa_hash    
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

