import time
import random
import threading
from modules.crypto_core import hashing
from modules.network import NetworkWorker


class AutoSyncDaemon:
    def __init__(self, network_worker: NetworkWorker, wait_seconds: int = 10, scan_seconds: int = 5):
        self.worker = network_worker
        self.wait_seconds = wait_seconds
        self.scan_seconds = scan_seconds
        self.is_running = False
        self.scanner_thread = None
        self.listener_thread = None
        self.last_synced = {}
        #^^tracks {peer_bytes: unix_timestamp} across cycles

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        
        self.scanner_thread = threading.Thread(
            target=self._daemon_loop,
            daemon=True,
            name="AutoSyncScanner"
        )
        self.scanner_thread.start()

        # 2. Start Outbound Priority Scanner
        self.scanner_thread = threading.Thread(
            target=self._daemon_loop,
            daemon=True,
            name="AutoSyncScanner"
        )
        self.scanner_thread.start()

    def stop(self):
        self.is_running = False

    def _daemon_loop(self):
        while self.is_running and self.worker.is_running:
            if not self.worker.sync_lock.locked():
                self._evaluate_and_sync_oldest()

            time.sleep(self.wait_seconds)


    def _evaluate_and_sync_oldest(self):
        # Scan strictly for the stealth _securevault-sync._tcp.local. service
        peers = self.worker.discovery.scan_for_devices(scan_time_seconds=self.scan_seconds, mode="SYNC")
        
        if not peers or self.worker.sync_lock.locked():
            return

        candidates = []
        current_time = time.time()
        
        # Minimum time between syncs with the SAME device to prevent Ping-Pong loops
        mesh_cooldown = self.wait_seconds + self.scan_seconds + 5  

        for raw_name, data in peers.items():
            raw_hash_str = data.get("ML-DSA-HASH", "")
            if not raw_hash_str:
                continue

            peer_bytes = hashing.hash_convert_bytes(raw_hash_str)
            ip = data["ip"]
            port = data["port"]

            #Priority 0: Compromised devices (sync immediately to nuke them)
            if self.worker.peers.check_if_compromised(peer_bytes):
                candidates.append((-1, random.random(), peer_bytes, ip, port))
                continue

            #Priority 1: Trusted devices
            trust_info = self.worker.peers.is_device_trusted(peer_bytes, self.worker.vault_id)
            if trust_info and trust_info.get("is_paused") != 1:
                last_seen = self.worker.peers.get_last_seen(peer_bytes, self.worker.vault_id) or 0
            
                #If we synced very recently, skip them this cycle
                if current_time - last_seen < mesh_cooldown:
                    continue

                candidates.append((last_seen, random.random(), peer_bytes, ip, port))

        if not candidates:
            return

        # Oldest timestamp surfaces to candidates[0]
        candidates.sort()
        _, _, target_hash, target_ip, target_port = candidates[0]

        # Jitter: 0.1s to 2.5s to prevent collision if multiple laptops wake up at once
        time.sleep(random.uniform(0.1, 2.5))

        if self.worker.sync_lock.locked():
            return

        # Dial out
        status = self.worker._route_outbound_connection(target_ip, target_port, target_hash)