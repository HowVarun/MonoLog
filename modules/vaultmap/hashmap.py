import msgpack

class VaultMap:
    def __init__(self):
        self.map = {}
    
    def add_file(self, virtual_path : str, chunk_data : list):
        self.map[virtual_path] =  chunk_data
    

    def delete_file(self, virtual_path : str, timestamp: int):
        if virtual_path in self.map:
            chunk = self.map.pop(virtual_path)
            self.map[f"{virtual_path}.del_{timestamp}"] = chunk
        
    def restitch(self, db_metadata : list):
        fullmap = {}
        for data in db_metadata:
            path = data["virtual_path"]
            fullmap[path] = {
                "size_bytes" : data["size_bytes"],
                "created_at" : data["created_at"],
                "is_active" :  data["is_active"],
                "meta_data" : self.map.get(path, [])
            }
        return msgpack.packb(fullmap, use_bin_type = True)
    
    def stitch(self, map_pt : bytes):
        full_map_dict = msgpack.unpackb(map_pt, raw = False, strict_map_key = False)
        self.map = {}
        for path, data in full_map_dict.items():
            self.map[path] = data.get("meta_data", [])
        return full_map_dict

    def get_meta(self, virtual_path : str):
        if virtual_path in self.map:
            return self.map.get(virtual_path)
        else:
            raise KeyError("Vitual Path does not exist")
        
    def destroy(self):
        if hasattr(self, 'map'):
            self.map.clear()
            self.map = {}
            
