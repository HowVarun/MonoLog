import msgpack
import struct

class VaultMap:
    def __init__(self):
        self.map = {}
    
    @staticmethod
    def fileid(uuid: bytes, v_ts: int) -> bytes:
        return struct.pack('>16sQ', uuid, v_ts)
        
    @staticmethod
    def uuid_time(fileid: bytes) -> tuple:
        return struct.unpack('>16sQ', fileid)
    
    def add_file(self, uuid: bytes, v_ts: int, chunk_data: list):
        _fileid = self.fileid(uuid, v_ts)
        self.map[_fileid] = chunk_data

    def restitch(self, db_metadata: list):
        fullmap = {}
        for data in db_metadata:
            _fileid = self.fileid(data["uuid"], data["v_ts"])
            
           
            fullmap[_fileid] = {
                "virtual_path": data["virtual_path"],
                "size_bytes": data["size_bytes"],
                "created_at": data["created_at"],
                "is_active":  data["is_active"],
                "meta_data": self.map.get(_fileid, [])
            }
        return msgpack.packb(fullmap, use_bin_type=True)

    #Stitching process : Creating the in-memory file locator in the .scaf file
    def stitch(self, map_pt: bytes):
        full_map_dict = msgpack.unpackb(map_pt, raw=False, strict_map_key=False)
        self.map = {}
        for _fileid, data in full_map_dict.items():
            self.map[_fileid] = data.get("meta_data", [])
        return full_map_dict

    def get_meta(self, uuid: bytes, v_ts: int):
        _fileid = self.fileid(uuid, v_ts)
        if _fileid in self.map:
            return self.map.get(_fileid)
        else:
            raise KeyError(f"File ID for UUID {uuid.hex()} at Timestamp {v_ts} does not exist in the map")

    def get_all_file_ids(self) -> list:
        return list(self.map.keys())
        
    def destroy(self):
        if hasattr(self, 'map'):
            self.map.clear()
            self.map = {}