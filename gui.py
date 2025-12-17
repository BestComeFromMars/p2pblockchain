# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import socket
import json
import time
import math

from block import Block
from blockchain import Blockchain
from peers import Peers

MY_IP_DEFAULT = "10.125.45.212"
BOOTSTRAP_IP_DEFAULT = "10.125.45.249"
DEFAULT_PORT = 5001

# Difficulty for demo: number of leading zeros required
DIFFICULTY_PREFIX = "00"


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

        # peers manager
        self.peers = Peers(local_ip=self.my_ip_value, local_port=self.port_value)

        # blockchain
        self.blockchain = Blockchain()

        # server
        self.running = False
        self.server_sock = None

        # mining state
        self.current_proposal = None          # Block object being proposed/mined locally
        self.mining_thread = None
        self.mining_stop_event = threading.Event()
        self.votes = {}                       # mapping peer -> bool (True=accept)
        self.vote_lock = threading.Lock()

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

        # bootstrap entries
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

        left = ttk.Frame(body, width=260, padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Peers").pack(anchor="w")
        self.peer_list = tk.Listbox(left, width=30, height=20)
        self.peer_list.pack(fill=tk.BOTH, expand=True)
        self.peer_list.bind("<<ListboxSelect>>", self.on_peer_list_select)

        # --- Send form: từ máy mình đến peer chọn ---
        self.send_frame = ttk.LabelFrame(left, text="Send from me → peer", padding=6)
        self.send_frame.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(self.send_frame, text="To:").grid(row=0, column=0, sticky="w")
        self.peer_combobox = ttk.Combobox(self.send_frame, width=20, state="readonly")
        self.peer_combobox.grid(row=0, column=1, padx=6, pady=2, sticky="w")

        ttk.Label(self.send_frame, text="Amount:").grid(row=1, column=0, sticky="w")
        self.amount_entry = ttk.Entry(self.send_frame, width=12)
        self.amount_entry.grid(row=1, column=1, padx=6, pady=2, sticky="w")

        ttk.Label(self.send_frame, text="Content:").grid(row=2, column=0, sticky="w")
        self.note_entry = ttk.Entry(self.send_frame, width=20)
        self.note_entry.grid(row=2, column=1, padx=6, pady=2, sticky="w")

        ttk.Button(self.send_frame, text="Send to selected", command=self.send_to_selected_peer).grid(
            row=3, column=0, columnspan=2, pady=(6, 0)
        )

        # Right panel (log + chain)
        right = ttk.Frame(body, padding=5)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(right, text="Event Log").pack(anchor="w")
        self.log_text = tk.Text(right, height=12, state=tk.DISABLED)
        self.log_text.pack(fill=tk.X)

        ttk.Label(right, text="Blockchain").pack(anchor="w", pady=(6, 0))
        self.chain_text = tk.Text(right, height=18)
        self.chain_text.pack(fill=tk.BOTH, expand=True)

    def _fill_defaults_into_entries(self):
        self.my_ip_entry.insert(0, self.my_ip_value)
        self.my_port_entry.insert(0, str(self.port_value))
        self.boot_ip_entry.insert(0, self.bootstrap_ip_value)
        self.boot_port_entry.insert(0, str(self.bootstrap_port_value))

    # ================= Helpers for peer UI =================
    def update_peer_combobox(self):
        values = [f"{ip}:{port}" for ip, port in self.peers.list() if (ip, port) != (self.my_ip_value, self.port_value)]
        try:
            self.peer_combobox['values'] = values
        except Exception:
            pass

    def on_peer_list_select(self, event):
        try:
            sel = self.peer_list.curselection()
            if not sel:
                return
            text = self.peer_list.get(sel[0])
            self.peer_combobox.set(text)
        except Exception:
            pass

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
            data="First block",
            previous_hash="0" * 64,
            nonce=0,
            miner="System",
        )
        g.hash = g.calculate_hash()
        self.blockchain.chain = [g]
        self.update_chain_view()

    def update_chain_view(self):
        self.chain_text.delete("1.0", tk.END)
        for b in self.blockchain.chain:
            # expects Block.to_pretty() exists
            try:
                self.chain_text.insert(tk.END, b.to_pretty() + "\n")
            except Exception:
                self.chain_text.insert(tk.END, str(b.to_dict()) + "\n\n")

    # ================= Networking / Server =================
    def start_node(self):
        self.my_ip_value = self.my_ip_entry.get().strip()
        try:
            self.port_value = int(self.my_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return

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
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except Exception as e:
                self.log(f"Accept loop error: {e}")

    def _handle_conn(self, conn, addr):
        try:
            raw = conn.recv(16384).decode().strip()
            if not raw:
                return
            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == "JOIN":
                ip, port = msg["ip"], msg["port"]
                self.peers.add(ip, port)
                self.update_peers_view()
                reply = {"type": "PEERS", "peers": self.peers.as_list()}
                conn.sendall(json.dumps(reply).encode())
                self.log(f"Peer joined: {ip}:{port}")

            elif mtype == "PEERS":
                peers_list = msg.get("peers", [])
                for p in peers_list:
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

            elif mtype == "PROPOSE":
                # A peer proposes a block header (without nonce/hash)
                prop = msg.get("proposal")
                if prop:
                    self.log(f"Received PROPOSE from {prop.get('miner')}, idx={prop.get('index')}")
                    # validate simple things
                    accept = False
                    last = self.blockchain.chain[-1]
                    try:
                        idx_ok = int(prop.get("index")) == last.index + 1
                        prev_ok = prop.get("previous_hash") == last.hash
                        # additional checks could be added (data format etc)
                        accept = idx_ok and prev_ok
                    except Exception:
                        accept = False

                    # send vote back (non-blocking)
                    vote_msg = {
                        "type": "VOTE",
                        "index": prop.get("index"),
                        "from": f"{self.my_ip_value}:{self.port_value}",
                        "vote": accept
                    }
                    try:
                        conn.sendall(json.dumps(vote_msg).encode())
                        self.log(f"Voted {'ACCEPT' if accept else 'REJECT'} to proposer {prop.get('miner')}")
                    except Exception:
                        pass

            elif mtype == "VOTE":
                # proposer receives votes
                voter = msg.get("from")
                vote_val = bool(msg.get("vote", False))
                with self.vote_lock:
                    self.votes[voter] = vote_val
                self.log(f"Vote from {voter}: {'ACCEPT' if vote_val else 'REJECT'}")

            elif mtype == "COMMIT":
                # a full committed block broadcast
                block_data = msg.get("block")
                if block_data:
                    last = self.blockchain.chain[-1]
                    # simple validation
                    if block_data.get("previous_hash") == last.hash and int(block_data.get("index")) == last.index + 1:
                        new_block = Block(
                            index=block_data.get("index"),
                            timestamp=block_data.get("timestamp"),
                            data=block_data.get("data"),
                            previous_hash=block_data.get("previous_hash"),
                            nonce=block_data.get("nonce", 0),
                            miner=block_data.get("miner", "unknown")
                        )
                        new_block.hash = block_data.get("hash", new_block.calculate_hash())
                        self.blockchain.chain.append(new_block)
                        self.update_chain_view()
                        self.log(f"Block #{new_block.index} COMMITTED from {block_data.get('miner')}")

                        # if we were mining same proposal, tell mining thread to stop
                        if self.current_proposal and self.current_proposal.previous_hash == new_block.previous_hash:
                            self.log("Commit received for candidate we were mining -> stop mining for that candidate")
                            self._stop_mining()
                    else:
                        self.log("Received COMMIT that does not match local chain - ignoring")
            # else ignore unknown
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

        try:
            msg = {"type": "JOIN", "ip": self.my_ip_value, "port": self.port_value}
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
                self.peers.add(boot_ip, boot_port)
                self.update_peers_view()
                self.log("Received peers list from bootstrap")

                for ip, port in self.peers.list():
                    if (ip, port) == (self.my_ip_value, self.port_value):
                        continue
                    threading.Thread(target=self._send_hello, args=(ip, port), daemon=True).start()

        except Exception as e:
            self.log(f"Join failed: {e}")

    def _send_hello(self, ip, port):
        try:
            msg = {"type": "HELLO", "ip": self.my_ip_value, "port": self.port_value}
            self._send_and_recv(ip, port, msg, timeout=2, expect_reply=False)
        except Exception as e:
            self.log(f"Hello to {ip}:{port} failed: {e}")

    # helper: send json and optionally receive reply (returns raw reply string or None)
    def _send_and_recv(self, ip, port, msg, timeout=3, expect_reply=True):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(json.dumps(msg).encode())
            data = None
            if expect_reply:
                data = s.recv(16384).decode()
            s.close()
            return data
        except Exception as e:
            # log but keep UI responsive
            self.log(f"Conn to {ip}:{port} failed: {e}")
            return None

    # ================= Peers UI =================
    def update_peers_view(self):
        self.peer_list.delete(0, tk.END)
        for ip, port in self.peers.list():
            self.peer_list.insert(tk.END, f"{ip}:{port}")
        self.update_peer_combobox()

    # ================= Demo helpers =================
    def _ui_add_demo_block(self):
        data = {"from": "Alice", "to": "Bob", "amount": 1, "ts": datetime.now().isoformat()}
        self.create_new_block_and_broadcast(data)

    def create_new_block_and_broadcast(self, data):
        last = self.blockchain.chain[-1]
        b = Block(index=last.index + 1,
                  timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  data=data,
                  previous_hash=last.hash,
                  nonce=0,
                  miner=f"{self.my_ip_value}:{self.port_value}"
                  )
        b.hash = b.calculate_hash()
        self.blockchain.chain.append(b)
        self.update_chain_view()
        self.log(f"New block created #{b.index} by {b.miner}")

        msg = {"type": "COMMIT", "block": b.to_dict()}
        for ip, port in self.peers.list():
            if (ip, port) == (self.my_ip_value, self.port_value):
                continue
            threading.Thread(target=self._send_and_recv, args=(ip, port, msg, 2, False), daemon=True).start()

    # ================= Mining / Proposal flow =================
    def send_to_selected_peer(self):
        dest = self.peer_combobox.get().strip()
        if not dest:
            messagebox.showwarning("No peer", "Please select a peer to send to.")
            return

        try:
            ip, port_s = dest.split(":")
            port = int(port_s)
        except Exception:
            messagebox.showerror("Invalid", "Peer format invalid. Use ip:port.")
            return

        amount_text = (self.amount_entry.get() or "").strip()
        note = (self.note_entry.get() or "").strip()

        if amount_text == "":
            messagebox.showwarning("No amount", "Please enter amount.")
            return

        try:
            amount = float(amount_text)
        except Exception:
            messagebox.showerror("Invalid amount", "Amount must be a number.")
            return

        # Build transaction data
        tx = {
            "from": f"{self.my_ip_value}:{self.port_value}",
            "to": dest,
            "amount": amount,
            "note": note,
            "ts": datetime.now().isoformat()
        }

        # Create proposal block (without nonce/hash yet)
        last = self.blockchain.chain[-1]
        proposal = Block(
            index=last.index + 1,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data=tx,
            previous_hash=last.hash,
            nonce=0,
            miner=f"{self.my_ip_value}:{self.port_value}"
        )
        # store current proposal and reset vote map
        self.current_proposal = proposal
        with self.vote_lock:
            self.votes = {}  # reset votes
            # count self as implicit vote True
            self.votes[f"{self.my_ip_value}:{self.port_value}"] = True

        # Broadcast PROPOSE to peers (ask for silent votes)
        prop_msg = {"type": "PROPOSE", "proposal": {
            "index": proposal.index,
            "previous_hash": proposal.previous_hash,
            "timestamp": proposal.timestamp,
            "miner": proposal.miner,
            "data": proposal.data
        }}
        self.log(f"PROPOSE block #{proposal.index} to peers - start mining")
        for ip_p, port_p in self.peers.list():
            if (ip_p, port_p) == (self.my_ip_value, self.port_value):
                continue
            threading.Thread(target=self._send_and_recv, args=(ip_p, port_p, prop_msg, 3, True), daemon=True).start()

        # start mining thread for this proposal
        self.mining_stop_event.clear()
        self.mining_thread = threading.Thread(target=self._mining_worker, args=(proposal,), daemon=True)
        self.mining_thread.start()

    def _mining_worker(self, proposal_block: Block):
        """
        Try nonces until find a hash with prefix DIFFICULTY_PREFIX.
        Mining does NOT stop until either:
         - a COMMIT for this proposal is received (self.mining_stop_event)
         - OR this node finds a valid nonce and also has >= majority votes -> then COMMIT.
        """
        self.log(f"Mining started on proposal #{proposal_block.index} (miner={proposal_block.miner})")
        # ensure current_proposal points to this
        self.current_proposal = proposal_block

        # simple mining loop - increment nonce
        try:
            while not self.mining_stop_event.is_set():
                # increment nonce and compute hash
                proposal_block.nonce += 1
                proposal_block.hash = proposal_block.calculate_hash()

                # found a valid hash?
                if proposal_block.hash.startswith(DIFFICULTY_PREFIX):
                    self.log(f"Found valid nonce {proposal_block.nonce} hash={proposal_block.hash[:12]}... for block #{proposal_block.index}")
                    # check votes
                    with self.vote_lock:
                        total_nodes = len(self.peers.list()) + 1  # peers + self
                        yes_votes = sum(1 for v in self.votes.values() if v)
                    needed = (total_nodes // 2) + 1
                    self.log(f"Votes yes={yes_votes}/{total_nodes} needed={needed}")
                    if yes_votes >= needed:
                        # commit: append to local chain and broadcast COMMIT
                        proposal_block.hash = proposal_block.hash  # already set
                        self.blockchain.chain.append(proposal_block)
                        self.update_chain_view()
                        self.log(f"Block #{proposal_block.index} COMMITTED by me")

                        commit_msg = {"type": "COMMIT", "block": proposal_block.to_dict()}
                        for ip_p, port_p in self.peers.list():
                            if (ip_p, port_p) == (self.my_ip_value, self.port_value):
                                continue
                            threading.Thread(target=self._send_and_recv, args=(ip_p, port_p, commit_msg, 2, False), daemon=True).start()

                        # stop mining for this proposal
                        self._stop_mining()
                        return
                    else:
                        # not enough votes yet - keep mining; votes may arrive later
                        self.log("Not enough votes yet to commit; continue mining")
                # lightweight sleep to yield CPU occasionally
                if proposal_block.nonce % 1000 == 0:
                    time.sleep(0.01)
            # loop end - stopped externally
            self.log("Mining thread exited (stop event set)")
        except Exception as e:
            self.log(f"Mining error: {e}")
        finally:
            # clear current proposal only if it matches
            if self.current_proposal and self.current_proposal.index == proposal_block.index:
                self.current_proposal = None

    def _stop_mining(self):
        """Signal mining thread (if any) to stop and wait briefly."""
        self.mining_stop_event.set()
        try:
            if self.mining_thread and self.mining_thread.is_alive():
                # give a moment to exit
                self.mining_thread.join(timeout=0.5)
        except Exception:
            pass
        self.mining_thread = None
        self.current_proposal = None

    # ================== End mining =================

if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
