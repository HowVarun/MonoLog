import qrcode
import hashlib
import socket

class MobileQRAnchor:
    def __init__(self, port=65432):
        self.port = port
        self.header = "SecureVault_V1.1"

    def generate_qr(self, ip_address: str, dsa_pub_key: bytes):

        sha_object = hashlib.sha3_256(dsa_pub_key)
        hash_dsa_pubk = sha_object.hexdigest()
        payload = f"{self.header}|{ip_address}:{self.port}|{hash_dsa_pubk}"
        
        print(f"[*] Generating QR Code for payload: {payload}")

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(payload)
        qr.make(fit=True)

        
        img = qr.make_image(fill_color="black", back_color="white")
        
        print("Opening QR Code in default image viewer...")
        img.show()

