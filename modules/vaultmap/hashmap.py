import msgpack

class VaultMap:
    def __init__(self):
        self.map = {}
    
    def add_file(self, file_id: bytes, chunk_data: list):
        self.map[file_id] = chunk_data


    def restitch(self, db_metadata: list):
        fullmap = {}
        for data in db_metadata:
            file_id = data["file_id"]
            
            # We bundle the dynamic string paths inside the payload 
            # so the vault always knows where this file is "located" virtually
            fullmap[file_id] = {
                "virtual_path": data["virtual_path"],
                "size_bytes": data["size_bytes"],
                "created_at": data["created_at"],
                "is_active":  data["is_active"],
                "meta_data": self.map.get(file_id, [])
            }
        return msgpack.packb(fullmap, use_bin_type=True)
    
    def stitch(self, map_pt: bytes):
        # Because we used use_bin_type=True in msgpack, the file_id byte arrays
        # will unpack perfectly back into Python bytes for our dictionary keys.
        full_map_dict = msgpack.unpackb(map_pt, raw=False, strict_map_key=False)
        self.map = {}
        for file_id, data in full_map_dict.items():
            self.map[file_id] = data.get("meta_data", [])
        return full_map_dict

    def get_meta(self, file_id: bytes):
        if file_id in self.map:
            return self.map.get(file_id)
        else:
            raise KeyError("File ID does not exist in the map")
        
    def destroy(self):
        if hasattr(self, 'map'):
            self.map.clear()
            self.map = {}