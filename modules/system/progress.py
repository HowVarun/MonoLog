from tqdm import tqdm

class TransferProgress:
    def __init__(self):
        self.active = False
        self.filename = ""
        self.pbar = None

    def start_transfer(self, filename: str, total_bytes: int, direction: str = "Downloading"):
        self.filename = filename
        self.active = True
        
        # tqdm automatically calculates MB/s and ETA based on update frequency
        self.pbar = tqdm(
            total=total_bytes,
            desc=f"[{direction}] {filename}",
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
            leave=True, 
            dynamic_ncols=True,
            miniters=1,
            mininterval=0.1
        )

    def add_bytes(self, amount: int):
        if self.active and self.pbar:
            self.pbar.update(amount)

    def end_transfer(self):
        self.active = False
        if self.pbar:
            self.pbar.close()
            self.pbar = None