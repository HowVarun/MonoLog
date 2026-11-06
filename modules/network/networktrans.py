import os
import struct
import socket
import time
from modules.system import Opcodes
from modules.crypto_core import AesGcm, MLKEM
onemb = 1024*1024

class SecureNetworkTransport:
    def __init__(self, sock: socket.socket = None, buffer_size: int = onemb):
        if sock:
            self.sock = sock
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aesgcm = None
            
        self.buffer = buffer_size

    def _configure_socket(self):
        try:
            #disabling nagle's algorithm
            self.sock.setsockopt(socket.IPROTO_TCP, socket.TCP_NODELAY, 1)
            #xpanding os kernel sliding window
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*onemb)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*onemb)
        except Exception as e:
            print(f"Network configuration failed {e}")

    def enable_tunnel_encryption(self, session_key: bytes):
        #activates AES-GCM Tunnel for all subsequent packets
        if len(session_key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self.aesgcm = AesGcm(session_key)
        # print("[*] Ephemeral AES-256-GCM Tunnel Established.")

    def send_message(self, opcode: bytes, data: bytes = b""):
        if len(opcode) != 5:
            print(f"[{Opcodes.ERR_PARSE.decode('utf-8')}] Opcode must be 5 bytes.")
            raise ValueError(f"Opcode {opcode} must be exactly 5 bytes long.")
            
        
        
        try:
            if self.aesgcm:
                # ================= TUNNEL MODE =================
                iv, ciph = self.aesgcm.encrypt_cipherstream(opcode+data)
                payload_length = len(iv) + len(ciph)
                header = struct.pack(">I", payload_length)
                # print(f"[NET-TX] Sent En-Opcode: {opcode.decode(errors='ignore')}") #debugg
                # print(time.time())

                if payload_length <= 4096:
                    self.sock.sendall(header + iv + ciph)
                else:
                    self.sock.sendall(header)
                    self.sock.sendall(iv + ciph)
            else:
                # ================= PLAINTEXT MODE =================
                # print(f"[NET-TX] Sent Opcode: {opcode.decode(errors='ignore')}") #debugg
                # print(time.time())
                # Coalesce small control packets; split large chunks to avoid 2 MB RAM copy
                payload_length = len(data)
                header = struct.pack(">I", payload_length) + opcode
                if payload_length <= 4096:
                    self.sock.sendall(header + data)
                else:
                    self.sock.sendall(header)
                    self.sock.sendall(data)
        except Exception as e:
            print(f"[{Opcodes.ERR_NET.decode('utf-8')}] Transport failed to send message: {e}")
            raise ConnectionError()

    def receive_message(self, timeout: float = 5.0) -> tuple[bytes, bytes]:
        if timeout:
            try:
                self.sock.settimeout(timeout)
            except OSError:
                pass
            
        try:
            header_bytes = self._recv_exactly(4)
            if not header_bytes:
                print(f"[{Opcodes.BYE_FORCE.decode('utf-8')}] Peer disconnected during header read.")
                self.close_connection()
                return Opcodes.BYE_FORCE, b""
                
            payload_length = struct.unpack(">I", header_bytes)[0]
            if payload_length > 16*onemb:
                raise ValueError(f"Payload length {payload_length} exceeds 16 MB safety limit.")

            if self.aesgcm:
                # ================= TUNNEL MODE =================
                enc_blob = self._recv_exactly(payload_length) if payload_length > 0 else b""
                if not enc_blob:
                    return Opcodes.BYE_FORCE, b""

                iv = enc_blob[:12]
                ciph = enc_blob[12:]
                try:
                    pt = self.aesgcm.decrypt_cipherstream(iv, ciph)
                except Exception as e:
                    raise PermissionError(f"Tunnel decryption failed Error : {e}")

                opcode = pt[:5]
                payload = pt[5:]
                # print(f"[NET-RX] Recv En-Opcode: {opcode.decode(errors='ignore')}") #debugg
                # print(time.time())
            else:
                # ================= PLAINTEXT MODE =================
                opcode = self._recv_exactly(5)
                if not opcode:
                    print(f"[{Opcodes.BYE_FORCE.decode('utf-8')}] Peer disconnected during opcode read.")
                    self.close_connection()
                    return Opcodes.BYE_FORCE, b""
                # print(f"[NET-RX] Recv Opcode: {opcode.decode(errors='ignore')}") #debugg
                # print(time.time())

                payload = self._recv_exactly(payload_length) if payload_length > 0 else b""
            # print("has returned recieve message") #debuggggg
            return opcode, payload
            
        except socket.timeout:
            print(f"[{Opcodes.ERR_NET.decode('utf-8')}] Socket read timed out.")
            self.close_connection()
            return Opcodes.ERR_NET, b""
        except ConnectionResetError:
            print(f"[{Opcodes.ERR_NET.decode('utf-8')}] Connection reset by peer.")
            self.close_connection()
            return Opcodes.ERR_NET, b""
        except Exception as e:
            import traceback
            traceback.print_exc() #DEUBGGG
            print(f"[{Opcodes.ERR_PARSE.decode('utf-8')}] Transport layer parse error: {e}")
            self.close_connection()
            return Opcodes.ERR_PARSE, b""
        finally:
            if timeout:
                try:
                    self.sock.settimeout(timeout)
                except OSError:
                    pass

    def _recv_exactly(self, n: int) -> bytes:
        buf = bytearray(n)
        view = memoryview(buf)
        pos = 0
        while pos < n:
            nbytes = self.sock.recv_into(view[pos:], min(self.buffer, n - pos))
            if not nbytes:
                return b""
            pos += nbytes
        return bytes(buf)

    def close_connection(self):
        try:
            self.sock.close()
        except Exception:
            pass