# block.py
import hashlib
import json
from datetime import datetime

# difficulty = number of leading zeros required in hex hash
DIFFICULTY = 3

class Block:
    def __init__(self, index: int, timestamp: str, data, previous_hash: str = "", nonce: int = 0, miner: str = None):
        self.index = int(index)
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = int(nonce)
        self.miner = miner
        self.hash = self.calculate_hash()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "miner": self.miner
        }

    def to_pretty(self):
        return (
            f"Block #{self.index}\n"
            f"Timestamp : {self.timestamp}\n"
            f"Miner     : {self.miner}\n"
            f"Nonce     : {self.nonce}\n"
            f"PrevHash  : {self.previous_hash}\n"
            f"Hash      : {self.hash}\n"
            f"Data      : {self.data}\n"
            + "-"*60
        )

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def calculate_hash(self):
        # deterministic serialization for data
        raw_data = json.dumps(self.data, sort_keys=True, separators=(",", ":"))
        raw = f"{self.index}{self.timestamp}{raw_data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def mine(self, difficulty: int = DIFFICULTY):
        prefix = "0" * difficulty
        # ensure nonce int
        if not isinstance(self.nonce, int):
            self.nonce = 0
        while True:
            self.hash = self.calculate_hash()
            if self.hash.startswith(prefix):
                return
            self.nonce += 1

    @classmethod
    def create_genesis(cls):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        b = cls(index=0, timestamp=ts, data={"genesis": True}, previous_hash="0"*64, nonce=0, miner="SYSTEM")
        b.hash = b.calculate_hash()
        return b
