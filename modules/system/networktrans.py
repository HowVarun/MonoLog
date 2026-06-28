import struct
import socket
from modules.system import Opcodes

class SecureNetworkTransport:
    def __init__(self, sock: socket.socket = None, buffer_size: int = 65536):
        if sock:
            self.sock = sock
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        self.buffer = buffer_size

    def send_message(self, opcode: bytes, data: bytes = b""):
        if len(opcode) != 5:
            print(f"[{Opcodes.ERR_PARSE.decode('utf-8')}] Opcode must be 5 bytes.")
            raise ValueError(f"Opcode {opcode} must be exactly 5 bytes long.")
            
        payload_length = len(data)
        header = struct.pack(">I", payload_length)
        
        try:
            self.sock.sendall(header + opcode + data)
        except Exception as e:
            print(f"[{Opcodes.ERR_NET.decode('utf-8')}] Transport failed to send message: {e}")
            raise ConnectionError()

    def receive_message(self, timeout: float = None) -> tuple[bytes, bytes]:
        if timeout:
            self.sock.settimeout(timeout)
            
        try:
            header_bytes = self._recv_exactly(4)
            if not header_bytes:
                print(f"[{Opcodes.BYE_FORCE.decode('utf-8')}] Peer disconnected during header read.")
                self.close_connection()
                return Opcodes.BYE_FORCE, b""
                
            payload_length = struct.unpack(">I", header_bytes)[0]
            
            opcode = self._recv_exactly(5)
            if not opcode:
                print(f"[{Opcodes.BYE_FORCE.decode('utf-8')}] Peer disconnected during opcode read.")
                self.close_connection()
                return Opcodes.BYE_FORCE, b""

            payload = self._recv_exactly(payload_length) if payload_length > 0 else b""
            
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
            print(f"[{Opcodes.ERR_PARSE.decode('utf-8')}] Transport layer parse error: {e}")
            self.close_connection()
            return Opcodes.ERR_PARSE, b""
        finally:
            if timeout:
                self.sock.settimeout(None)

    def _recv_exactly(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            remaining = n - len(data)
            chunk = self.sock.recv(min(self.buffer, remaining))
            if not chunk:
                return b"" 
            data.extend(chunk)
        return bytes(data)

    def close_connection(self):
        try:
            self.sock.close()
        except Exception:
            pass