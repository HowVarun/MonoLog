
import struct
import os 

class VaultIO:
    def __init__(self, filepath : str):
        self.filepath = filepath
        
    
    @staticmethod
    def conditional_format(input_str, format_char):
        return [int(part) for part in input_str.split(format_char)]
    
    def initialize_new_vault(self, version, salt, pointer_iv, pointer_ciphertext):
        major, minor, patch = self.conditional_format(version, ".")
        header_format = '>4sBBB16s12s32s'
        cipher_stream = struct.pack(
            header_format,
            b"SCAF",
            major,
            minor,
            patch,
            salt,
            pointer_iv,
            pointer_ciphertext
        )

        with open(self.filepath, 'wb') as nfile:
            nfile.write(cipher_stream)

    def read_header(self) -> tuple:
        header_format = '>4sBBB16s'
        with open(self.filepath, 'rb') as rfile:
            header = rfile.read(23)  
            output = struct.unpack(header_format, header)
        return output  

    def read_pointer(self) -> tuple:
        header_format = '>12s32s'
        with open(self.filepath, 'rb') as rfile:
            rfile.seek(23)
            pointer = rfile.read(44)
            output = struct.unpack(header_format, pointer)
        return output  
    
    def append_cargo(self, encrypted_chunk : bytes):
        with open(self.filepath, 'ab') as afile:
            afile.write(encrypted_chunk) #assuming that while editing, cargo added first, hash appended later
            os.fsync(afile.fileno())
    
    def append_map(self, iv : bytes, encrypted_chunk : bytes):
        with open(self.filepath, 'ab') as afile:
            afile.write(iv)
            afile.write(encrypted_chunk) 
            os.fsync(afile.fileno())
    
    def write_pointer(self, iv_identifier, identifier_ct):
        header_format = '>12s32s'
        byte = struct.pack(header_format, iv_identifier, identifier_ct)
        with open(self.filepath, 'r+b') as f:
            f.seek(23)
            f.write(byte)
            os.fsync(f.fileno())
    

    def read_cargo(self, start_byte, end_byte):
        byte_len = end_byte - start_byte
        with open(self.filepath, 'rb') as rfile:
            rfile.seek(start_byte)
            stream = rfile.read(byte_len)
        return stream
    
    def read_map(self, pointer_offset, pointer_length):
        with open(self.filepath, 'rb') as rfile:
            rfile.seek(pointer_offset)
            if pointer_length is None:
                stream = rfile.read()
            elif pointer_length < 0:
                # negative length not allowed
                raise ValueError("pointer_length must be non-negative or None")
            else:
                stream = rfile.read(pointer_length)
        return stream
    
    def get_eof(self):
        with open(self.filepath, 'rb') as rfile:
            rfile.seek(0,2)
            eof = rfile.tell()
        return eof
                
    def atomic_map_swap(self, nmap_pointer_iv, nmap_pointer_cipher, nmap_pointer, nmap_iv, nmap_cipher):
        backup_path = self.filepath + ".bak"
        with open(self.filepath, 'r+b') as f:
            f.seek(23)
            map_pointer_iv = f.read(12)
            map_pointer_cipher = f.read(32)
        
        backup_format = f'>12s32s'
        backup_stream = struct.pack(backup_format,
                                map_pointer_iv,
                                map_pointer_cipher
                                )

        with open(backup_path, 'wb') as bak:
            bak.write(backup_stream)
            os.fsync(bak.fileno())
    
        with open(self.filepath, 'r+b') as f:
            f.seek(nmap_pointer)
            f.write(nmap_iv)
            f.write(nmap_cipher)
            f.seek(23)
            f.write(nmap_pointer_iv)
            f.write(nmap_pointer_cipher)
            os.fsync(f.fileno())
            
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except OSError:
                pass
    
    def rescue_vault(self):
        bak_path = self.filepath + ".bak"
        
        if not os.path.exists(bak_path):
            raise FileNotFoundError(f" Backup file {bak_path} not found.")
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f" Main vault {self.filepath} not found.")
            
        with open(bak_path, 'rb') as bak_file:
            bak_data = bak_file.read()
            
        pointer_iv = bak_data[:12]
        pointer_cipher = bak_data[12:44]
        
        with open(self.filepath, 'r+b') as vault_file:
            vault_file.seek(23)
            vault_file.write(pointer_iv)
            vault_file.write(pointer_cipher)
            os.fsync(vault_file.fileno())
            
        return True
