# peers.py
from typing import List, Tuple

class Peers:
    def __init__(self, local_ip: str = None, local_port: int = None):
        # dynamic list (start empty)
        self.peers: List[Tuple[str, int]] = []
        self.local = (local_ip, local_port)

    def add(self, ip: str, port: int):
        tup = (ip, int(port))
        if tup != self.local and tup not in self.peers:
            self.peers.append(tup)

    def remove(self, ip: str, port: int):
        tup = (ip, int(port))
        if tup in self.peers:
            self.peers.remove(tup)

    def list(self):
        return self.peers.copy()

    def as_list(self):
        return [[ip, port] for ip, port in self.peers]
