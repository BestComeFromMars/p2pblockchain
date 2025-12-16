# simple peers helper for demo
from typing import List, Tuple

class Peers:
    def __init__(self, local_ip: str = None, local_port: int = None):
        self.peers: List[Tuple[str, int]] = []
        self.local = (local_ip, local_port)

    def add(self, ip: str, port: int):
        if (ip, port) not in self.peers and (ip, port) != self.local:
            self.peers.append((ip, port))

    def remove(self, ip: str, port: int):
        if (ip, port) in self.peers:
            self.peers.remove((ip, port))

    def list(self):
        return self.peers.copy()
