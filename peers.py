class Peers:
    def __init__(self, local_ip=None, local_port=None):
        self.peers = []
        self.local = (local_ip, local_port)

    def add(self, ip, port):
        if (ip, port) != self.local and (ip, port) not in self.peers:
            self.peers.append((ip, port))

    def remove(self, ip, port):
        if (ip, port) in self.peers:
            self.peers.remove((ip, port))

    def list(self):
        return self.peers.copy()

    def as_list(self):
        return list(self.peers)
