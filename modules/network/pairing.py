import socket
from .networktrans import SecureNetworkTransport
from modules.crypto_core import SasPass

class PQCHandshake:
    def __init__(self, port = 65432):
        self.port = port
        self.sas = SasPass()
    
    #Phase 0 : TCP Discovery
    def start_host_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", 65432))
        server_sock.listen(1)
        client_sock, client_address = server_sock.accept()
        server_sock.close()

        return SecureNetworkTransport(sock = client_sock)   #We have the client_sock object which we recieved via TCP we can do whatever now
    
    def connect_to_host(self, address : str):
        client_sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((address, self.port))

        return SecureNetworkTransport(sock = client_sock)   #We have the client_sock object which we recieved via TCP we can do whatever now
    
    #Phase 1 : Initial Pairing
    def host_pair(self, transport : SecureNetworkTransport, dsa_pub_key : bytes):
        transport.send_message(dsa_pub_key)
        client_pub_key = transport.recieve_message()
        if not client_pub_key:
            transport.close_connection()
        
        print_pin = self.sas.derive_pass(dsa_pub_key, client_pub_key)
        print(print_pin)
        verdict = transport.recieve_message()
        if verdict == b"AUTH_SUCCESS":
            return client_pub_key
        else:
            transport.close_connection()
            return False
    
    def client_pair(self, transport : SecureNetworkTransport, dsa_pub_key : bytes):
        host_pub_key = transport.recieve_message()
        if not host_pub_key:
            transport.close_connection()
            return False
        transport.send_message(dsa_pub_key)
        user_input = input("Please enter the PIN displayed on the other device")
        if self.sas.verify_pass(user_input, dsa_pub_key, host_pub_key):
            transport.send_message(b"AUTH_SUCCESS")
            return host_pub_key
        else:
            transport.close_connection()
            return False    
