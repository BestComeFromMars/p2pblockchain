import hashlib
import time
import json
from datetime import datetime

DIFFICULTY = 3

class Block:
    def __init__(self, index: int, timestamp: float, data, previous_hash: str = "", nonce: int = 0, miner: str = None):
        self.index = index
        self.timestamp = timestamp  # store as ISO string or float
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
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
            f"{'-'*60}\n"
        )


    def to_json(self):
        # deterministic serialization for hashing/network
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def calculate_hash(self):
        if self.index == 0:
            return "0" * 64
        raw = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True, separators=(',', ':'))}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def mine(self, difficulty=DIFFICULTY):
        prefix = "0" * difficulty
        # ensure nonce is int
        if not isinstance(self.nonce, int):
            self.nonce = 0
        while True:
            self.hash = self.calculate_hash()
            if self.hash.startswith(prefix):
                return
            self.nonce += 1

    @classmethod
    def create_new_block(cls, index: int, prev_block, data, miner: str = None, difficulty=DIFFICULTY):
        prev_hash = prev_block.hash if prev_block is not None else ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        b = cls(index=index, timestamp=timestamp, data=data, previous_hash=prev_hash, nonce=0, miner=miner)
        # Mine synchronously here (demo) — can be moved to a thread if desired
        b.mine(difficulty=difficulty)
        return b
