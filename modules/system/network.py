import struct
import socket

class SecureNetworkTransport:
    def __init__(self, sock = None):
        if sock:
            self.sock = sock
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buffer = 2*1024*1024
    
    def send_message(self, data : bytes):
        data_len = struct.pack(">I", len(data))
        data_payload = data_len + data
        self.sock.sendall(data_payload)
    
    def recieve_message(self, timeout= None):
        if timeout:
            self.sock.settimeout(timeout)
        data_len_packed = self.sock.recv(4)
        if not data_len_packed or len(data_len_packed) < 4:
            return b""
        data_len = struct.unpack(">I", data_len_packed)[0]
        data = bytearray()
        while len(data) < data_len:
            remaining = data_len - len(data)
            chunk = self.sock.recv(min(self.buffer, remaining))

            if not chunk:
                return b""
            
            data.extend(chunk)
        if timeout:
            self.sock.settimeout(None)
        
        return bytes(data)
    
    def close_connection(self):
        self.sock.close()