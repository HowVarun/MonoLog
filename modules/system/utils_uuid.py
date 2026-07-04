import uuid6

class IDGenerator:
    @staticmethod
    def generate_file_id() -> bytes:
        # Returns exactly 16 raw bytes
        return uuid6.uuid7().bytes