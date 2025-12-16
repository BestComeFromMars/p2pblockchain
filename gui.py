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

# Default local ip placeholder (can be changed in UI)
MY_IP_DEFAULT = "127.0.0.1"

# simple protocol notes:
# - JSON messages, each message sent as length-prefixed or newline-terminated.
# - For simplicity we send newline-terminated JSON strings.

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Transfer Simulator (P2P Demo)")
        self.root.geometry("1200x700")

        # ----- defaults -----
        self.my_ip_value = MY_IP_DEFAULT
        self.port_value = 5001

        self.bootstrap_ip_value = MY_IP_DEFAULT
        self.bootstrap_port_value = 5002

        # peers manager
        self.peers = Peers(local_ip=self.my_ip_value, local_port=self.port_value)

        # blockchain instance
        self.blockchain = Blockchain()

        # votes store: block_hash -> list of (voter_ip, 'yes'/'no')
        self.votes_lock = threading.Lock()
        self.votes = {}

        # server socket thread control
        self.server_thread = None
        self.server_sock = None
        self.running = False

        # build UI
        self.build_head()
        self.build_body()
        self._fill_defaults_into_entries()

        # initialize with genesis block
        self.create_genesis()

    # ========== UI ==========
    def build_head(self):
        head = ttk.Frame(self.root, padding=5)
        head.pack(fill=tk.X)

        ttk.Label(head, text="MY_IP").grid(row=0, column=0, padx=2)
        self.my_ip_entry = ttk.Entry(head, width=15)
        self.my_ip_entry.grid(row=0, column=1)

        ttk.Label(head, text="PORT").grid(row=0, column=2, padx=2)
        self.my_port_entry = ttk.Entry(head, width=6)
        self.my_port_entry.grid(row=0, column=3)

        ttk.Button(head, text="Start Node", command=self.start_node).grid(row=0, column=4, padx=5)

        ttk.Label(head, text="BootstrapIP").grid(row=0, column=5, padx=2)
        self.boot_ip_entry = ttk.Entry(head, width=15)
        self.boot_ip_entry.grid(row=0, column=6)

        ttk.Label(head, text="PORT").grid(row=0, column=7, padx=2)
        self.boot_port_entry = ttk.Entry(head, width=6)
        self.boot_port_entry.grid(row=0, column=8)

        ttk.Button(head, text="Join", command=self.join_network).grid(row=0, column=9, padx=2)
        ttk.Button(head, text="Leave", command=self.leave_network).grid(row=0, column=10, padx=2)

    def build_body(self):
        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, width=220, padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Label(left, text="Peers").pack(anchor="w")
        self.peer_list = tk.Listbox(left, width=25)
        self.peer_list.pack(fill=tk.BOTH, expand=True)

        right = ttk.Frame(body, padding=5)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Log
        ttk.Label(right, text="Event Log").pack(anchor="w")
        lframe = ttk.Frame(right)
        lframe.pack(fill=tk.BOTH, expand=False)
        self.log_text = tk.Text(lframe, height=8, state=tk.DISABLED, wrap="word")
        scroll = ttk.Scrollbar(lframe, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Chain view
        ttk.Label(right, text="Blockchain").pack(anchor="w", pady=(6,0))
        cframe = ttk.Frame(right)
        cframe.pack(fill=tk.BOTH, expand=True)
        self.chain_text = tk.Text(cframe, height=12, wrap="none")
        cscroll = ttk.Scrollbar(cframe, command=self.chain_text.yview)
        self.chain_text.config(yscrollcommand=cscroll.set)
        self.chain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Transfer form
        tframe = ttk.LabelFrame(right, text="Transfer")
        tframe.pack(fill=tk.X, pady=6)
        ttk.Label(tframe, text="From").grid(row=0, column=0, padx=2, pady=2, sticky="e")
        self.from_entry = ttk.Entry(tframe, width=25)
        self.from_entry.grid(row=0, column=1, padx=2, pady=2)
        ttk.Label(tframe, text="To").grid(row=0, column=2, padx=2, pady=2, sticky="e")
        self.to_entry = ttk.Entry(tframe, width=25)
        self.to_entry.grid(row=0, column=3, padx=2, pady=2)
        ttk.Label(tframe, text="Amount").grid(row=1, column=0, padx=2, pady=2, sticky="e")
        self.amount_entry = ttk.Entry(tframe, width=12)
        self.amount_entry.grid(row=1, column=1, padx=2, pady=2, sticky="w")
        ttk.Label(tframe, text="Data").grid(row=1, column=2, padx=2, pady=2, sticky="e")
        self.data_entry = ttk.Entry(tframe, width=25)
        self.data_entry.grid(row=1, column=3, padx=2, pady=2)
        ttk.Button(tframe, text="Send", command=self.send_tx).grid(row=2, column=3, sticky="e", padx=2, pady=4)

    def _fill_defaults_into_entries(self):
        self.my_ip_entry.delete(0, tk.END)
        self.my_ip_entry.insert(0, self.my_ip_value)
        self.my_port_entry.delete(0, tk.END)
        self.my_port_entry.insert(0, str(self.port_value))
        self.boot_ip_entry.delete(0, tk.END)
        self.boot_ip_entry.insert(0, self.bootstrap_ip_value)
        self.boot_port_entry.delete(0, tk.END)
        self.boot_port_entry.insert(0, str(self.bootstrap_port_value))
        self.from_entry.delete(0, tk.END)
        self.from_entry.insert(0, self.my_ip_value)

    # ========== Logging and chain UI ==========
    def log(self, msg: str):
        time_str = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{time_str}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_chain_view(self):
        chain = self.blockchain.chain
        self.chain_text.delete("1.0", tk.END)
        if not chain:
            self.chain_text.insert(tk.END, "(empty chain)\n")
            return
        for block in chain:
            b = block.to_dict()
            self.chain_text.insert(
                tk.END,
                f"Index: {b['index']}\nTime: {b['timestamp']}\nMiner: {b['miner']}\nData: {b['data']}\nPrev: {b['previous_hash']}\nHash: {b['hash']}\n{'-'*40}\n"
            )

    def update_peers_view(self):
        plist = self.peers.list()
        self.peer_list.delete(0, tk.END)
        for i, (ip, port) in enumerate(plist):
            display = f"{ip}:{port}"
            if ip == self.my_ip_value and port == self.port_value:
                display += " (ME)"
            self.peer_list.insert(tk.END, display)
            try:
                if ip == self.my_ip_value and port == self.port_value:
                    self.peer_list.itemconfig(i, {'bg': 'lightgreen'})
            except Exception:
                pass

    # ========== Blockchain helpers ==========
    def create_genesis(self):
        genesis = Block(index=0, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        data={"genesis": True}, previous_hash="0"*64, nonce=0, miner="genesis")
        # For genesis, we can precompute hash but not necessarily require pow
        genesis.hash = genesis.calculate_hash()
        self.blockchain.chain = [genesis]
        self.update_chain_view()

    # ========== Networking (simple TCP JSON newline protocol) ==========
    def start_node(self):
        ip = self.my_ip_entry.get().strip()
        port_s = self.my_port_entry.get().strip()
        if not ip:
            messagebox.showwarning("Lỗi", "MY_IP trống")
            return
        try:
            port = int(port_s)
        except:
            messagebox.showwarning("Lỗi", "PORT phải là số")
            return

        self.my_ip_value = ip
        self.port_value = port
        self.peers.local = (self.my_ip_value, self.port_value)
        # add self to peers list so UI highlights it
        self.peers.add(self.my_ip_value, self.port_value)
        self.update_peers_view()

        # start server thread
        if not self.running:
            self.running = True
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            self.log(f"Node started at {self.my_ip_value}:{self.port_value}")
        else:
            self.log("Node already running")

    def stop_node(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
        self.log("Node stopped")

    def _server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.my_ip_value, self.port_value))
            sock.listen(5)
            self.server_sock = sock
            self.log(f"Listening on {self.my_ip_value}:{self.port_value}")
        except Exception as e:
            self.log(f"Failed to bind server socket: {e}")
            self.running = False
            return

        while self.running:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_conn(self, conn: socket.socket, addr):
        # read newline-terminated JSONs
        with conn:
            data = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # process each newline terminated json
                    while b"\n" in data:
                        line, data = data.split(b"\n", 1)
                        try:
                            msg = json.loads(line.decode("utf-8"))
                            self._handle_message(msg, addr)
                        except Exception as e:
                            self.log(f"Bad message from {addr}: {e}")
            except Exception as e:
                self.log(f"Connection error {addr}: {e}")

    def _handle_message(self, msg: dict, addr):
        mtype = msg.get("type")
        sender = msg.get("sender")
        if mtype == "tx":
            # received transaction broadcast
            self.log(f"Received TX from {sender}: {msg.get('data')}")
            # we could add to mempool; for demo we just acknowledge
            # optionally re-broadcast
        elif mtype == "proposal":
            # someone proposes a mined block -> auto-vote (demo)
            block_dict = msg.get("block")
            self.log(f"Received proposal for block {block_dict.get('index')} from {sender}")
            # quick validation: ensure previous hash matches our last block (simple)
            prev = self.blockchain.last_block()
            if prev and block_dict.get("previous_hash") != prev.hash:
                # conflicting chain: reject
                vote = "no"
            else:
                vote = "yes"
            # send vote back
            vote_msg = {"type": "vote", "block_hash": block_dict.get("hash"), "vote": vote, "sender": f"{self.my_ip_value}:{self.port_value}"}
            # reply directly to proposer (addr may be proposer)
            self._send_direct(addr[0], addr[1], vote_msg)
            self.log(f"Voted {vote} for {block_dict.get('hash')} to {sender}")
        elif mtype == "vote":
            # collect votes
            block_hash = msg.get("block_hash")
            voter = msg.get("sender")
            vote_val = msg.get("vote")
            with self.votes_lock:
                self.votes.setdefault(block_hash, []).append((voter, vote_val))
            self.log(f"Received vote {vote_val} from {voter} for {block_hash}")
        elif mtype == "new_block":
            # someone announces new block -> attempt to append
            block_dict = msg.get("block")
            # reconstruct Block object
            b = Block(index=block_dict["index"],
                      timestamp=block_dict["timestamp"],
                      data=block_dict["data"],
                      previous_hash=block_dict["previous_hash"],
                      nonce=block_dict.get("nonce", 0),
                      miner=block_dict.get("miner"))
            b.hash = block_dict["hash"]
            # try append
            if self.blockchain.append_block(b):
                self.log(f"Appended new block {b.index} from network")
                self.update_chain_view()
            else:
                self.log(f"Rejected new block {b.index} from network (invalid)")

        elif mtype == "peer_request":
            # reply with our known peers
            resp = {"type": "peer_response", "peers": [{"ip": p[0], "port": p[1]} for p in self.peers.list()], "sender": f"{self.my_ip_value}:{self.port_value}"}
            self._send_direct(addr[0], addr[1], resp)
        elif mtype == "peer_response":
            plist = msg.get("peers", [])
            for p in plist:
                try:
                    ip = p.get("ip")
                    port = int(p.get("port"))
                    self.peers.add(ip, port)
                except:
                    pass
            self.update_peers_view()
            self.log(f"Updated peers from {sender}")
        else:
            self.log(f"Unknown message type from {sender}: {mtype}")

    def _send_direct(self, ip: str, port: int, msg: dict):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            s.close()
        except Exception as e:
            self.log(f"Direct send to {ip}:{port} failed: {e}")

    def broadcast(self, msg: dict):
        # send to known peers
        plist = self.peers.list()
        for (ip, port) in plist:
            # skip self
            if ip == self.my_ip_value and port == self.port_value:
                continue
            threading.Thread(target=self._send_direct, args=(ip, port, msg), daemon=True).start()

    # ========== Join / Leave network (simple) ==========
    def join_network(self):
        boot_ip = self.boot_ip_entry.get().strip()
        boot_port_s = self.boot_port_entry.get().strip()
        if not boot_ip:
            messagebox.showwarning("Lỗi", "BootstrapIP trống")
            return
        try:
            boot_port = int(boot_port_s)
        except:
            messagebox.showwarning("Lỗi", "Bootstrap PORT phải là số")
            return

        # contact bootstrap and request peers
        try:
            req = {"type": "peer_request", "sender": f"{self.my_ip_value}:{self.port_value}"}
            self._send_direct(boot_ip, boot_port, req)
            # also add bootstrap
            self.peers.add(boot_ip, boot_port)
            self.update_peers_view()
            self.log(f"Requested peers from bootstrap {boot_ip}:{boot_port}")
        except Exception as e:
            self.log(f"Join network failed: {e}")

    def leave_network(self):
        boot_ip = self.boot_ip_entry.get().strip()
        try:
            boot_port = int(self.boot_port_entry.get().strip())
        except:
            boot_port = None
        if boot_port:
            self.peers.remove(boot_ip, boot_port)
        self.update_peers_view()
        self.log("Left network (local removal)")

    # ========== Block proposal / voting flow ==========
    def send_tx(self):
        from_addr = self.from_entry.get().strip()
        to_addr = self.to_entry.get().strip()
        amount = self.amount_entry.get().strip()
        text = self.data_entry.get().strip()
        if not from_addr or not to_addr or not amount:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng điền From, To và Amount trước khi gửi")
            return

        tx_data = {"from": from_addr, "to": to_addr, "amount": amount, "text": text}
        self.log(f"Nhận giao dịch mới: {tx_data}")

        # broadcast tx to peers
        tx_msg = {"type": "tx", "data": tx_data, "sender": f"{self.my_ip_value}:{self.port_value}"}
        self.broadcast(tx_msg)
        self.log("Broadcasted TX to peers")

        # start mining after 5s (simulate waiting window to propagate tx)
        self.log("Bắt đầu đào sau 5s (trong lúc này gửi thông tin giao dịch đến các node khác)")
        t = threading.Timer(5.0, self._start_mining_and_propose, args=(tx_data,))
        t.start()

    def _start_mining_and_propose(self, tx_data):
        # create proposal block (mine locally)
        index = len(self.blockchain.chain)
        prev = self.blockchain.last_block()
        miner = f"{self.my_ip_value}:{self.port_value}"
        # create block and mine (this blocks the thread while mining)
        proposal = Block.create_new_block(index=index, prev_block=prev, data=tx_data, miner=miner)
        self.log(f"Mined proposal block {proposal.index} hash={proposal.hash}")

        # broadcast proposal to peers
        prop_msg = {"type": "proposal", "block": proposal.to_dict(), "sender": f"{self.my_ip_value}:{self.port_value}"}
        self.broadcast(prop_msg)
        self.log("Broadcasted proposal to peers, collecting votes...")

        # initialize votes list for this block and include our own vote (yes)
        with self.votes_lock:
            self.votes.setdefault(proposal.hash, [])
            self.votes[proposal.hash].append((f"{self.my_ip_value}:{self.port_value}", "yes"))

        # wait a short time to collect votes, then decide (demo: 3 seconds)
        decision_timer = threading.Timer(3.0, self._decide_on_proposal, args=(proposal,))
        decision_timer.start()

    def _decide_on_proposal(self, proposal):
        with self.votes_lock:
            vlist = self.votes.get(proposal.hash, []).copy()

        prev_block = self.blockchain.last_block()
        # convert votes to expected format for Blockchain.check_block_votes (list of tuples)
        if self.blockchain.check_block_votes(vlist, proposal, prev_block):
            # commit block
            appended = self.blockchain.append_block(proposal)
            if appended:
                self.log(f"Thông báo đã thêm block {proposal.index} vào chains")
                self.update_chain_view()
                # broadcast new_block to peers
                msg = {"type": "new_block", "block": proposal.to_dict(), "sender": f"{self.my_ip_value}:{self.port_value}"}
                self.broadcast(msg)
            else:
                self.log("Local append failed (maybe chain changed)")
        else:
            self.log("Proposal rejected by votes — will retry or wait")

        # cleanup votes for this block
        with self.votes_lock:
            if proposal.hash in self.votes:
                del self.votes[proposal.hash]

    # ========== Utilities ==========
    def send_direct_message_to_peer(self, ip, port, msg):
        self._send_direct(ip, port, msg)

# ========== Run ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
