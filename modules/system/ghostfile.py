import tempfile
import secrets
import os
from pathlib import Path
import sys
import subprocess

class GhostFileIO:
    def __init__(self):
        self._tempdir_obj = tempfile.TemporaryDirectory()
        self.tempdir = Path(self._tempdir_obj.name)
        self.writechunk = 2*1024*1024  
    
    def create_ghost_path(self, filename):
        basename = secrets.token_hex(16)
        filebase, filebase_extension = os.path.splitext(filename)
        ghost_filepath = os.path.join(self.tempdir, f"{basename}{filebase_extension}")
        return str(ghost_filepath)
    
    def write_decrypted_chunk(self, path, chunk):
        with open(path, 'ab') as tmp:
            tmp.write(chunk)


    def secure_shred(self, path):
        if not os.path.exists(path):
            return False
        else:
            filesize = os.path.getsize(path)
            with open(path, 'r+b') as tmp:
                for i in range(0, filesize, self.writechunk):
                    bytes_to_write  = min(self.writechunk, filesize - tmp.tell())
                    tmp.write(b'\x00' * bytes_to_write)
                os.fsync(tmp.fileno())
            os.remove(path)

    def wipe_session(self):
        for path in self.tempdir.rglob('*'):
            if path.is_file():
                self.secure_shred(path)
        self._tempdir_obj.cleanup()
    
    def launch_file(self, path):
        if sys.platform == "win32": #for windows
            os.startfile(path)
        elif sys.platform == "darwin": # macOS
            subprocess.call(["open", path])
        else: 
            subprocess.call(["xdg-open", path]) #for linux