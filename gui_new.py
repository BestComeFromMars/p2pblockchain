import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import socket
import json
import time

from block import Block
from blockchain import Blockchain
from peers import Peers


MY_IP_DEFAULT = "10.125.45.212"
BOOTSTRAP_IP_DEFAULT = "10.125.45.249"
DEFAULT_PORT = 5001


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Transfer Simulator (P2P Demo)")
        self.root.geometry("1200x700")

        # ----- defaults -----
        self.my_ip_value = MY_IP_DEFAULT
        self.port_value = DEFAULT_PORT

        self.bootstrap_ip_value = BOOTSTRAP_IP_DEFAULT
        self.bootstrap_port_value = DEFAULT_PORT

        # peers manager (Peers class expected to manage list & local tuple)
        self.peers = Peers(local_ip=self.my_ip_value, local_port=self.port_value)

        # blockchain
        self.blockchain = Blockchain()

        # server
        self.running = False
        self.server_sock = None

        # UI
        self.build_head()
        self.build_body()
        self._fill_defaults_into_entries()

        self.create_genesis()

    # ================= UI =================
    def build_head(self):
        head = ttk.Frame(self.root, padding=5)
        head.pack(fill=tk.X)

        ttk.Label(head, text="MY_IP").grid(row=0, column=0)
        self.my_ip_entry = ttk.Entry(head, width=15)
        self.my_ip_entry.grid(row=0, column=1)

        ttk.Label(head, text="PORT").grid(row=0, column=2)
        self.my_port_entry = ttk.Entry(head, width=6)
        self.my_port_entry.grid(row=0, column=3)

        ttk.Button(head, text="Start Node", command=self.start_node).grid(row=0, column=4, padx=5)

        # bootstrap entries (needed to join network)
        ttk.Label(head, text="BootstrapIP").grid(row=0, column=5)
        self.boot_ip_entry = ttk.Entry(head, width=15)
        self.boot_ip_entry.grid(row=0, column=6)

        ttk.Label(head, text="PORT").grid(row=0, column=7)
        self.boot_port_entry = ttk.Entry(head, width=6)
        self.boot_port_entry.grid(row=0, column=8)

        ttk.Button(head, text="Join", command=self.join_network).grid(row=0, column=9, padx=2)

        # quick-test add block button (optional)
        ttk.Button(head, text="Add Demo Block", command=self._ui_add_demo_block).grid(row=0, column=10, padx=6)

    def build_body(self):
        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, width=220, padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Peers").pack(anchor="w")
        self.peer_list = tk.Listbox(left, width=30)
        self.peer_list.pack(fill=tk.BOTH, expand=True)

        right = ttk.Frame(body, padding=5)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(right, text="Event Log").pack(anchor="w")
        self.log_text = tk.Text(right, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.X)

        ttk.Label(right, text="Blockchain").pack(anchor="w", pady=(6, 0))
        self.chain_text = tk.Text(right, height=15)
        self.chain_text.pack(fill=tk.BOTH, expand=True)

    def _fill_defaults_into_entries(self):
        self.my_ip_entry.insert(0, self.my_ip_value)
        self.my_port_entry.insert(0, str(self.port_value))
        self.boot_ip_entry.insert(0, self.bootstrap_ip_value)
        self.boot_port_entry.insert(0, str(self.bootstrap_port_value))

    # ================= Logging =================
    def log(self, msg):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{t}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ================= Blockchain =================
    def create_genesis(self):
        g = Block(
            index=0,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data={"genesis": True},
            previous_hash="0" * 64,
            nonce=0,
            miner="genesis",
        )
        self.blockchain.chain = [g]
        self.update_chain_view()

    def update_chain_view(self):
        self.chain_text.delete("1.0", tk.END)
        for b in self.blockchain.chain:
            self.chain_text.insert(tk.END, f"{b.to_dict()}\n\n")

    # ================= Networking =================
    def start_node(self):
        # update local ip/port from UI
        self.my_ip_value = self.my_ip_entry.get().strip()
        try:
            self.port_value = int(self.my_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return

        # update peers.local
        self.peers.local = (self.my_ip_value, self.port_value)

        if not self.running:
            self.running = True
            threading.Thread(target=self._server_loop, daemon=True).start()
            self.log(f"Node started at {self.my_ip_value}:{self.port_value}")

    def _server_loop(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.my_ip_value, self.port_value))
            self.server_sock.listen(20)
        except Exception as e:
            self.log(f"Server bind/listen failed: {e}")
            self.running = False
            return

        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                # handle each connection in separate thread so one slow peer doesn't block accept
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except Exception as e:
                self.log(f"Accept loop error: {e}")

    def _handle_conn(self, conn, addr):
        try:
            data = conn.recv(8192).decode().strip()
            if not data:
                return

            msg = json.loads(data)
            mtype = msg.get("type")

            if mtype == "JOIN":
                ip, port = msg["ip"], msg["port"]
                self.peers.add(ip, port)
                self.update_peers_view()

                reply = {
                    "type": "PEERS",
                    "peers": self.peers.as_list()
                }
                conn.sendall(json.dumps(reply).encode())
                self.log(f"Peer joined: {ip}:{port}")

            elif mtype == "PEERS":
                # a peer can send a peers list (not used often in this demo)
                peers_list = msg.get("peers", [])
                for p in peers_list:
                    # accept both [ip,port] and ["ip","port"] etc
                    try:
                        ip, port = p[0], int(p[1])
                        self.peers.add(ip, port)
                    except Exception:
                        continue
                self.update_peers_view()
                self.log("Received peers list")

            elif mtype == "HELLO":
                ip, port = msg["ip"], msg["port"]
                self.peers.add(ip, port)
                self.update_peers_view()
                self.log(f"Handshake with {ip}:{port}")

            elif mtype == "NEW_BLOCK":
                # simple demo: accept if previous_hash matches last
                block_data = msg.get("block")
                if block_data:
                    last = self.blockchain.chain[-1]
                    if block_data.get("previous_hash") == last.hash:
                        # construct Block object (assumes Block constructor signature matches)
                        new_block = Block(
                            index=block_data.get("index"),
                            timestamp=block_data.get("timestamp"),
                            data=block_data.get("data"),
                            previous_hash=block_data.get("previous_hash"),
                            nonce=block_data.get("nonce", 0),
                            miner=block_data.get("miner", "unknown")
                        )
                        # ensure hash from block_data is used if Block.calculate_hash differs
                        new_block.hash = block_data.get("hash", new_block.calculate_hash())
                        self.blockchain.chain.append(new_block)
                        self.update_chain_view()
                        self.log(f"Block #{new_block.index} added from peer {addr[0]}")
                    else:
                        self.log("Rejected block: previous_hash mismatch")
            # else: ignore unknown types
        except json.JSONDecodeError:
            self.log("Received invalid JSON")
        except Exception as e:
            self.log(f"Connection handler error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

    def join_network(self):
        boot_ip = self.boot_ip_entry.get().strip()
        try:
            boot_port = int(self.boot_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid bootstrap port")
            return

        if (boot_ip, boot_port) == (self.my_ip_value, self.port_value):
            self.log("Bootstrap equals self - skipping join")
            return

        # connect to bootstrap and request peer list
        try:
            msg = {
                "type": "JOIN",
                "ip": self.my_ip_value,
                "port": self.port_value
            }
            resp = self._send_and_recv(boot_ip, boot_port, msg, timeout=3)
            if not resp:
                self.log(f"Join failed: no response from bootstrap {boot_ip}:{boot_port}")
                return

            try:
                data = json.loads(resp)
            except json.JSONDecodeError:
                self.log("Bootstrap returned invalid JSON")
                return

            if data.get("type") == "PEERS":
                peers_list = data.get("peers", [])
                for p in peers_list:
                    try:
                        ip, port = p[0], int(p[1])
                        self.peers.add(ip, port)
                    except Exception:
                        continue

                # also ensure bootstrap itself is added
                self.peers.add(boot_ip, boot_port)

                self.update_peers_view()
                self.log("Received peers list from bootstrap")

                # send HELLO to known peers (non-blocking)
                for ip, port in self.peers.list():
                    # don't handshake with self
                    if (ip, port) == (self.my_ip_value, self.port_value):
                        continue
                    threading.Thread(target=self._send_hello, args=(ip, port), daemon=True).start()

        except Exception as e:
            self.log(f"Join failed: {e}")

    def _send_hello(self, ip, port):
        try:
            msg = {
                "type": "HELLO",
                "ip": self.my_ip_value,
                "port": self.port_value
            }
            self._send_and_recv(ip, port, msg, timeout=2, expect_reply=False)
            # optionally, we can request peer's peers by sending {"type":"PEERS_REQUEST"} etc.
        except Exception as e:
            self.log(f"Hello to {ip}:{port} failed: {e}")

    # helper: send json and optionally receive reply (returns raw reply string or None)
    def _send_and_recv(self, ip, port, msg, timeout=3, expect_reply=True):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(json.dumps(msg).encode())
            if expect_reply:
                data = s.recv(8192).decode()
            else:
                data = None
            s.close()
            return data
        except Exception as e:
            # don't spam logs for every small failure, but record some info
            self.log(f"Conn to {ip}:{port} failed: {e}")
            return None

    # ================= Peers UI =================
    def update_peers_view(self):
        self.peer_list.delete(0, tk.END)
        for ip, port in self.peers.list():
            self.peer_list.insert(tk.END, f"{ip}:{port}")

    # ================= Demo helpers =================
    def _ui_add_demo_block(self):
        # quick demo block data
        data = {
            "from": "Alice",
            "to": "Bob",
            "amount": 1,
            "ts": datetime.now().isoformat()
        }
        self.create_new_block_and_broadcast(data)

    def create_new_block_and_broadcast(self, data):
        last = self.blockchain.chain[-1]
        b = Block(
            index=last.index + 1,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data=data,
            previous_hash=last.hash,
            nonce=0,
            miner=f"{self.my_ip_value}:{self.port_value}"
        )
        # ensure block has proper hash (depends on Block implementation)
        b.hash = b.calculate_hash()
        self.blockchain.chain.append(b)
        self.update_chain_view()
        self.log(f"New block created #{b.index}")

        # broadcast NEW_BLOCK to peers (non-blocking)
        msg = {"type": "NEW_BLOCK", "block": b.to_dict()}
        for ip, port in self.peers.list():
            # skip self
            if (ip, port) == (self.my_ip_value, self.port_value):
                continue
            threading.Thread(target=self._send_and_recv, args=(ip, port, msg, 2, False), daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
