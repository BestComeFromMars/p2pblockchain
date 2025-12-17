# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import socket
import json
import time

from block import Block, DIFFICULTY
from blockchain import Blockchain
from peers import Peers

# ================= GLOBAL CONFIG =================
MY_IP_DEFAULT = "10.125.45.212"
BOOTSTRAP_IP_DEFAULT = "10.125.45.212"
DEFAULT_PORT = 5001

# message types
MSG_JOIN = "JOIN"
MSG_PEERS = "PEERS"
MSG_HELLO = "HELLO"
MSG_PROPOSE = "PROPOSE"
MSG_VOTE = "VOTE"     # used as reply to PROPOSE (contains ack + vote)
MSG_START = "START"   # tells peers to actually start mining their stored proposal
MSG_COMMIT = "COMMIT"
MSG_BLOCK = "NEW_BLOCK"  # legacy direct block broadcast

# ================= GUI / Node =================
class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Transfer Simulator (P2P Demo)")
        self.root.geometry("1200x700")

        # node identity
        self.node_name = socket.gethostname()

        # defaults
        self.my_ip_value = MY_IP_DEFAULT
        self.port_value = DEFAULT_PORT
        self.bootstrap_ip_value = BOOTSTRAP_IP_DEFAULT
        self.bootstrap_port_value = DEFAULT_PORT

        # peers and blockchain
        self.peers = Peers(local_ip=self.my_ip_value, local_port=self.port_value)
        # mapping (ip,port) -> name
        self.peer_info = {}
        self.blockchain = Blockchain(difficulty=DIFFICULTY)

        # server
        self.running = False
        self.server_sock = None

        # mining/proposal/vote state
        self.current_proposal = None          # Block object stored when PROPOSE received or created
        self.mining_thread = None
        self.mining_stop_event = threading.Event()
        self.votes = {}                       # dict voter_id -> bool (collected votes)
        self.vote_lock = threading.Lock()

        # UI build
        self.build_head()
        self.build_body()
        self._fill_defaults_into_entries()

        # NOTE: No genesis block creation here (user requested)

    # ---------- UI ----------
    def build_head(self):
        head = ttk.Frame(self.root, padding=5)
        head.pack(fill=tk.X)

        ttk.Label(head, text="MY_IP").grid(row=0, column=0)
        self.my_ip_entry = ttk.Entry(head, width=15); self.my_ip_entry.grid(row=0, column=1)

        ttk.Label(head, text="PORT").grid(row=0, column=2)
        self.my_port_entry = ttk.Entry(head, width=6); self.my_port_entry.grid(row=0, column=3)

        ttk.Button(head, text="Start Node", command=self.start_node).grid(row=0, column=4, padx=5)

        ttk.Label(head, text="BootstrapIP").grid(row=0, column=5)
        self.boot_ip_entry = ttk.Entry(head, width=15); self.boot_ip_entry.grid(row=0, column=6)

        ttk.Label(head, text="PORT").grid(row=0, column=7)
        self.boot_port_entry = ttk.Entry(head, width=6); self.boot_port_entry.grid(row=0, column=8)

        ttk.Button(head, text="Join", command=self.join_network).grid(row=0, column=9, padx=2)

        ttk.Button(head, text="Send Demo TX", command=self._ui_add_demo_block).grid(row=0, column=10, padx=6)

    def build_body(self):
        body = ttk.Frame(self.root); body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, width=360, padding=5); left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Peers").pack(anchor="w")
        self.peer_list = tk.Listbox(left, width=40, height=20); self.peer_list.pack(fill=tk.BOTH, expand=True)
        self.peer_list.bind("<<ListboxSelect>>", self.on_peer_list_select)

        self.send_frame = ttk.LabelFrame(left, text="Send from me → peer", padding=6)
        self.send_frame.pack(fill=tk.X, pady=(8,0))

        ttk.Label(self.send_frame, text="To:").grid(row=0, column=0, sticky="w")
        self.peer_combobox = ttk.Combobox(self.send_frame, width=26, state="readonly"); self.peer_combobox.grid(row=0, column=1, padx=6, pady=2)

        ttk.Label(self.send_frame, text="Amount:").grid(row=1, column=0, sticky="w")
        self.amount_entry = ttk.Entry(self.send_frame, width=12); self.amount_entry.grid(row=1, column=1, padx=6, pady=2)

        ttk.Label(self.send_frame, text="Content:").grid(row=2, column=0, sticky="w")
        self.note_entry = ttk.Entry(self.send_frame, width=26); self.note_entry.grid(row=2, column=1, padx=6, pady=2)

        ttk.Button(self.send_frame, text="Send to selected", command=self.send_to_selected_peer).grid(row=3, column=0, columnspan=2, pady=(6,0))

        right = ttk.Frame(body, padding=5); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(right, text="Event Log").pack(anchor="w")
        self.log_text = tk.Text(right, height=12, state=tk.DISABLED); self.log_text.pack(fill=tk.X)

        ttk.Label(right, text="Blockchain").pack(anchor="w", pady=(6,0))
        self.chain_text = tk.Text(right, height=18); self.chain_text.pack(fill=tk.BOTH, expand=True)

    def _fill_defaults_into_entries(self):
        self.my_ip_entry.insert(0, self.my_ip_value)
        self.my_port_entry.insert(0, str(self.port_value))
        self.boot_ip_entry.insert(0, self.bootstrap_ip_value)
        self.boot_port_entry.insert(0, str(self.bootstrap_port_value))

    # UI-safe call helper
    def ui_call(self, func, *args, **kwargs):
        self.root.after(0, lambda: func(*args, **kwargs))

    # ---------- logging / view ----------
    def log(self, msg):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{t}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_chain_view(self):
        self.chain_text.delete("1.0", tk.END)
        for b in self.blockchain.chain:
            try:
                self.chain_text.insert(tk.END, b.to_pretty() + "\n")
            except Exception:
                self.chain_text.insert(tk.END, str(b.to_dict()) + "\n\n")

    def update_peers_view(self):
        # Show name (ip:port) in listbox
        self.peer_list.delete(0, tk.END)
        entries = []
        for ip, port in self.peers.list():
            name = self.peer_info.get((ip, port), f"{ip}:{port}")
            label = f"{name} ({ip}:{port})"
            entries.append((label, f"{ip}:{port}"))
            self.peer_list.insert(tk.END, label)

        # Combobox values are ip:port strings for connection, but labels in listbox show names
        vals = [f"{ip}:{port}" for ip, port in self.peers.list() if (ip, port) != (self.my_ip_value, self.port_value)]
        try:
            self.peer_combobox['values'] = vals
        except Exception:
            pass

    # ---------- blockchain helpers ----------
    def _serialize_chain(self):
        return [b.to_dict() for b in self.blockchain.chain]

    def _deserialize_chain_and_validate(self, chain_list):
        """
        Try to build Block objects from list of dicts and validate sequentially.
        Return list_of_Block if valid else None.
        """
        try:
            temp = []
            for idx, d in enumerate(chain_list):
                b = Block(
                    index=int(d["index"]),
                    timestamp=d["timestamp"],
                    data=d["data"],
                    previous_hash=d["previous_hash"],
                    nonce=int(d.get("nonce", 0)),
                    miner=d.get("miner")
                )
                b.hash = d.get("hash", b.calculate_hash())
                # validate PoW if not genesis-like (allow genesis if index==0)
                if idx == 0:
                    # index 0 can be anything in this demo
                    temp.append(b)
                else:
                    prev = temp[-1]
                    # validate continuity
                    if b.index != prev.index + 1 or b.previous_hash != prev.hash:
                        return None
                    # check PoW validity using blockchain rules
                    if not self.blockchain.is_valid_pow(b):
                        return None
                    temp.append(b)
            return temp
        except Exception:
            return None

    # ---------- networking / server ----------
    def start_node(self):
        self.my_ip_value = self.my_ip_entry.get().strip()
        try:
            self.port_value = int(self.my_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return

        # update peers.local and ensure self included
        self.peers.local = (self.my_ip_value, self.port_value)
        self.peer_info[(self.my_ip_value, self.port_value)] = self.node_name
        self.peers.add(self.my_ip_value, self.port_value)  # ensure self present

        if not self.running:
            self.running = True
            threading.Thread(target=self._server_loop, daemon=True).start()
            self.ui_call(self.log, f"Node started at {self.my_ip_value}:{self.port_value} ({self.node_name})")
            self.ui_call(self.update_peers_view)

    def _server_loop(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.my_ip_value, self.port_value))
            self.server_sock.listen(20)
        except Exception as e:
            self.ui_call(self.log, f"Server bind/listen failed: {e}")
            self.running = False
            return

        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except Exception as e:
                self.ui_call(self.log, f"Accept loop error: {e}")

    def _handle_conn(self, conn, addr):
        """
        Handles incoming messages:
         - JOIN / PEERS / HELLO
         - PROPOSE: store proposal, reply VOTE (ack+vote) but DO NOT start mining
         - START: tells peer to start mining the stored proposal
         - VOTE: if proposer - record
         - COMMIT: append and stop mining
         - (legacy) NEW_BLOCK: direct append attempt
        """
        try:
            raw = conn.recv(32768).decode().strip()
            if not raw:
                return
            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == MSG_JOIN:
                ip, port = msg["ip"], int(msg["port"])
                name = msg.get("name", f"{ip}:{port}")
                self.peers.add(ip, port)
                self.peer_info[(ip, port)] = name
                self.ui_call(self.update_peers_view)
                # reply with peers list + chain for synchronization
                peers_payload = []
                for p_ip, p_port in self.peers.list():
                    p_name = self.peer_info.get((p_ip, p_port), "")
                    peers_payload.append([p_ip, p_port, p_name])
                reply = {"type": MSG_PEERS, "peers": peers_payload, "chain": self._serialize_chain()}
                conn.sendall(json.dumps(reply).encode())
                self.ui_call(self.log, f"Peer joined: {name} ({ip}:{port})")

            elif mtype == MSG_PEERS:
                # Received peers list and maybe chain (from bootstrap)
                peers_list = msg.get("peers", [])
                for p in peers_list:
                    try:
                        ip, port = p[0], int(p[1])
                        name = p[2] if len(p) > 2 else f"{ip}:{port}"
                        self.peers.add(ip, port)
                        self.peer_info[(ip, port)] = name
                    except Exception:
                        continue
                # chain syncing
                remote_chain = msg.get("chain", [])
                if remote_chain:
                    cand = self._deserialize_chain_and_validate(remote_chain)
                    if cand and len(cand) > len(self.blockchain.chain):
                        self.blockchain.chain = cand
                        self.ui_call(self.log, f"Replaced local chain with remote chain (len={len(cand)})")
                        self.ui_call(self.update_chain_view)
                self.ui_call(self.update_peers_view)
                self.ui_call(self.log, "Received peers list (and chain)")

            elif mtype == MSG_HELLO:
                ip, port = msg["ip"], int(msg["port"])
                name = msg.get("name", f"{ip}:{port}")
                self.peers.add(ip, port)
                self.peer_info[(ip, port)] = name
                self.ui_call(self.update_peers_view)
                self.ui_call(self.log, f"Handshake with {name} ({ip}:{port})")

            elif mtype == MSG_PROPOSE:
                prop = msg.get("proposal")
                proposer_name = msg.get("name", msg.get("proposal", {}).get("miner", "unknown"))
                proposer_addr = msg.get("from", None)
                if prop:
                    # reconstruct Block and store locally as current_proposal (synchronization)
                    try:
                        newprop = Block(
                            index=int(prop.get("index")),
                            timestamp=prop.get("timestamp"),
                            data=prop.get("data"),
                            previous_hash=prop.get("previous_hash"),
                            nonce=0,
                            miner=prop.get("miner")
                        )
                    except Exception:
                        newprop = None

                    if newprop:
                        with self.vote_lock:
                            # store proposal but DO NOT start mining until START arrives
                            self.current_proposal = newprop
                        self.ui_call(self.log, f"Stored PROPOSAL #{newprop.index} from {proposer_name} (waiting for START)")

                        # validate minimal things then reply vote (acts as ack + vote)
                        accept = False
                        prev = self.blockchain.last_block()
                        try:
                            idx_ok = newprop.index == (prev.index + 1 if prev else 0)
                            prev_ok = newprop.previous_hash == (prev.hash if prev else ("0"*64))
                            accept = bool(idx_ok and prev_ok)
                        except Exception:
                            accept = False

                        vote_msg = {"type": MSG_VOTE, "vote": accept, "from": f"{self.my_ip_value}:{self.port_value}", "name": self.node_name}
                        try:
                            conn.sendall(json.dumps(vote_msg).encode())
                            self.ui_call(self.log, f"Replied ACK/VOTE {'ACCEPT' if accept else 'REJECT'} for proposal #{newprop.index}")
                        except Exception as e:
                            self.ui_call(self.log, f"Failed to send vote reply: {e}")
                    else:
                        self.ui_call(self.log, "Malformed proposal received")

            elif mtype == MSG_START:
                # coordinator says start mining the stored proposal
                start_idx = msg.get("index")
                self.ui_call(self.log, f"Received START for #{start_idx}")
                with self.vote_lock:
                    if self.current_proposal and self.current_proposal.index == int(start_idx):
                        self.ui_call(self.log, f"Starting mining for stored proposal #{start_idx}")
                        # ensure not already mining
                        if not (self.mining_thread and self.mining_thread.is_alive()):
                            self.mining_stop_event.clear()
                            self.mining_thread = threading.Thread(target=self._mining_worker, args=(self.current_proposal,), daemon=True)
                            self.mining_thread.start()
                    else:
                        self.ui_call(self.log, f"START for #{start_idx} but no matching stored proposal - ignoring")

            elif mtype == MSG_VOTE:
                voter = msg.get("from")
                vote_val = bool(msg.get("vote", False))
                name = msg.get("name", None)
                if voter:
                    with self.vote_lock:
                        self.votes[voter] = vote_val
                    if name:
                        # try to map name to ip:port if possible
                        try:
                            ip_s, port_s = voter.split(":")
                            self.peer_info[(ip_s, int(port_s))] = name
                            self.ui_call(self.update_peers_view)
                        except Exception:
                            pass
                self.ui_call(self.log, f"Vote from {name or voter}: {'ACCEPT' if vote_val else 'REJECT'}")

            elif mtype == MSG_COMMIT:
                block_data = msg.get("block")
                if block_data:
                    try:
                        new_block = Block(
                            index=int(block_data["index"]),
                            timestamp=block_data["timestamp"],
                            data=block_data["data"],
                            previous_hash=block_data["previous_hash"],
                            nonce=int(block_data.get("nonce", 0)),
                            miner=block_data.get("miner")
                        )
                        new_block.hash = block_data.get("hash", new_block.calculate_hash())
                        appended = self.blockchain.append_block(new_block)
                        if appended:
                            self.ui_call(self.log, f"COMMIT received: block #{new_block.index} appended")
                            self.ui_call(self.update_chain_view)
                            # stop mining if we were mining this index
                            with self.vote_lock:
                                if self.current_proposal and self.current_proposal.index == new_block.index:
                                    self.ui_call(self.log, "Commit matches our candidate -> stopping mining for that candidate")
                                    self._stop_mining()
                        else:
                            self.ui_call(self.log, f"COMMIT received but rejected block #{new_block.index}")
                    except Exception as e:
                        self.ui_call(self.log, f"Error processing COMMIT: {e}")

            elif mtype == MSG_BLOCK:
                # legacy direct block broadcast (already mined + commit)
                block_data = msg.get("block")
                if block_data:
                    try:
                        new_block = Block(
                            index=int(block_data["index"]),
                            timestamp=block_data["timestamp"],
                            data=block_data["data"],
                            previous_hash=block_data["previous_hash"],
                            nonce=int(block_data.get("nonce", 0)),
                            miner=block_data.get("miner")
                        )
                        new_block.hash = block_data.get("hash", new_block.calculate_hash())
                        appended = self.blockchain.append_block(new_block)
                        if appended:
                            self.ui_call(self.log, f"Received block #{new_block.index} APPENDED (legacy)")
                            self.ui_call(self.update_chain_view)
                        else:
                            self.ui_call(self.log, f"Block #{new_block.index} REJECTED (legacy)")
                    except Exception as e:
                        self.ui_call(self.log, f"Error processing incoming block: {e}")

        except json.JSONDecodeError:
            self.ui_call(self.log, "Received invalid JSON")
        except Exception as e:
            self.ui_call(self.log, f"Connection handler error: {e}")
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
            # include name in JOIN
            msg = {"type": MSG_JOIN, "ip": self.my_ip_value, "port": self.port_value, "name": self.node_name}
            resp = self._send_and_recv(boot_ip, boot_port, msg, timeout=3)
            if not resp:
                self.ui_call(self.log, f"Join failed: no response from bootstrap {boot_ip}:{boot_port}")
                return

            try:
                data = json.loads(resp)
            except json.JSONDecodeError:
                self.ui_call(self.log, "Bootstrap returned invalid JSON")
                return

            if data.get("type") == MSG_PEERS:
                for p in data.get("peers", []):
                    try:
                        ip, port = p[0], int(p[1])
                        name = p[2] if len(p) > 2 else f"{ip}:{port}"
                        self.peers.add(ip, port)
                        self.peer_info[(ip, port)] = name
                    except Exception:
                        continue

                # ensure bootstrap itself is included
                self.peers.add(boot_ip, boot_port)
                self.peer_info[(boot_ip, boot_port)] = data.get("peers", [[],[]])[0][2] if data.get("peers") else self.peer_info.get((boot_ip, boot_port), "bootstrap")

                # chain sync if provided
                remote_chain = data.get("chain", [])
                if remote_chain:
                    cand = self._deserialize_chain_and_validate(remote_chain)
                    if cand and len(cand) > len(self.blockchain.chain):
                        self.blockchain.chain = cand
                        self.ui_call(self.log, f"Synced chain from bootstrap (len={len(cand)})")
                        self.ui_call(self.update_chain_view)

                self.ui_call(self.update_peers_view)
                self.ui_call(self.log, "Received peers list from bootstrap")

                # send HELLO to known peers (non-blocking)
                for ip, port in self.peers.list():
                    if (ip, port) == (self.my_ip_value, self.port_value):
                        continue
                    threading.Thread(target=self._send_hello, args=(ip, port), daemon=True).start()

        except Exception as e:
            self.ui_call(self.log, f"Join failed: {e}")

    def _send_hello(self, ip, port):
        try:
            msg = {"type": MSG_HELLO, "ip": self.my_ip_value, "port": self.port_value, "name": self.node_name}
            self._send_and_recv(ip, port, msg, timeout=2, expect_reply=False)
        except Exception as e:
            self.ui_call(self.log, f"Hello to {ip}:{port} failed: {e}")

    def _send_and_recv(self, ip, port, msg, timeout=3, expect_reply=True):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(json.dumps(msg).encode())
            data = None
            if expect_reply:
                data = s.recv(32768).decode()
            s.close()
            return data
        except Exception as e:
            # log but don't crash
            self.ui_call(self.log, f"Conn to {ip}:{port} failed: {e}")
            return None

    # ---------- UI helpers ----------
    def on_peer_list_select(self, event):
        try:
            sel = self.peer_list.curselection()
            if not sel:
                return
            text = self.peer_list.get(sel[0])
            # extract ip:port from label "(ip:port)"
            if "(" in text and ")" in text:
                addr = text.split("(")[-1].strip(")")
                self.peer_combobox.set(addr)
            else:
                self.peer_combobox.set(text)
        except Exception:
            pass

    # ---------- propose / wait-for-acks / start / mine / commit ----------
    def send_to_selected_peer(self):
        dest = self.peer_combobox.get().strip()
        if not dest:
            messagebox.showwarning("No peer", "Please select a peer to send to.")
            return

        try:
            ip, port_s = dest.split(":"); port = int(port_s)
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

        tx = {
            "from": f"{self.my_ip_value}:{self.port_value}",
            "to": dest,
            "amount": amount,
            "note": note,
            "ts": datetime.now().isoformat()
        }

        prev = self.blockchain.last_block()
        idx = (prev.index + 1) if prev else 0
        # data is the note so it's simple for demo
        proposal = Block(
            index=idx,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data=tx["note"],
            previous_hash=prev.hash if prev else ("0"*64),
            nonce=0,
            miner=f"{self.my_ip_value}:{self.port_value}"
        )

        # propose -> wait ACKs -> send START -> start local mining
        threading.Thread(target=self._propose_wait_start_and_mine, args=(proposal,), daemon=True).start()

    def _propose_wait_start_and_mine(self, proposal: Block, per_peer_timeout=3):
        peers_list = [p for p in self.peers.list() if p != (self.my_ip_value, self.port_value)]
        total_peers = len(peers_list)
        self.ui_call(self.log, f"Sending PROPOSE #{proposal.index} to {total_peers} peers and waiting for ACKs")

        with self.vote_lock:
            self.current_proposal = proposal
            self.votes = {}
            self.votes[f"{self.my_ip_value}:{self.port_value}"] = True

        prop_msg = {"type": MSG_PROPOSE, "proposal": {
            "index": proposal.index,
            "previous_hash": proposal.previous_hash,
            "timestamp": proposal.timestamp,
            "miner": proposal.miner,
            "data": proposal.data
        }, "name": self.node_name, "from": f"{self.my_ip_value}:{self.port_value}"}

        ack_count = 0
        # sequential sending to collect replies reliably
        for ip_p, port_p in peers_list:
            try:
                resp = self._send_and_recv(ip_p, port_p, prop_msg, timeout=per_peer_timeout, expect_reply=True)
                if not resp:
                    self.ui_call(self.log, f"No reply (no ACK) from {ip_p}:{port_p}")
                    continue
                try:
                    reply = json.loads(resp)
                except json.JSONDecodeError:
                    self.ui_call(self.log, f"Invalid reply from {ip_p}:{port_p}")
                    continue

                if reply.get("type") == MSG_VOTE:
                    voter = reply.get("from")
                    vote_val = bool(reply.get("vote", False))
                    voter_name = reply.get("name", None)
                    with self.vote_lock:
                        self.votes[voter] = vote_val
                    ack_count += 1
                    if voter_name:
                        try:
                            ip_s, port_s = voter.split(":")
                            self.peer_info[(ip_s, int(port_s))] = voter_name
                            self.ui_call(self.update_peers_view)
                        except Exception:
                            pass
                    self.ui_call(self.log, f"ACK/VOTE from {voter_name or voter}: {'ACCEPT' if vote_val else 'REJECT'}")
                else:
                    self.ui_call(self.log, f"Unexpected reply type from {ip_p}:{port_p}: {reply.get('type')}")
            except Exception as e:
                self.ui_call(self.log, f"Error contacting {ip_p}:{port_p}: {e}")

        if ack_count != total_peers:
            self.ui_call(self.log, f"PROPOSE aborted: only {ack_count}/{total_peers} peers ACKed")
            with self.vote_lock:
                self.current_proposal = None
                self.votes = {}
            return

        # all acked -> store proposal locally (already stored) and tell peers to START
        self.ui_call(self.log, f"All {total_peers} peers ACKed PROPOSE #{proposal.index} -> sending START")
        start_msg = {"type": MSG_START, "index": proposal.index, "name": self.node_name}
        for ip_p, port_p in peers_list:
            threading.Thread(target=self._send_and_recv, args=(ip_p, port_p, start_msg, 2, False), daemon=True).start()

        # start mining locally as well
        self.ui_call(self.log, "Starting local mining after START broadcast")
        self.mining_stop_event.clear()
        self.mining_thread = threading.Thread(target=self._mining_worker, args=(proposal,), daemon=True)
        self.mining_thread.start()

    def _mining_worker(self, proposal_block: Block):
        self.ui_call(self.log, f"Mining started for proposal #{proposal_block.index}")
        try:
            while not self.mining_stop_event.is_set():
                proposal_block.nonce += 1
                proposal_block.hash = proposal_block.calculate_hash()

                if proposal_block.hash.startswith("0" * DIFFICULTY):
                    with self.vote_lock:
                        total_nodes = len(self.peers.list())  # peers list already includes self
                        yes_votes = sum(1 for v in self.votes.values() if v) + 1
                    needed = total_nodes  # strict all-nodes requirement (you can change to majority)
                    self.ui_call(self.log, f"Found nonce {proposal_block.nonce} for #{proposal_block.index} (hash={proposal_block.hash[:12]}...) votes_yes={yes_votes}/{total_nodes} need={needed}")
                    if yes_votes >= needed:
                        self.ui_call(self.log, f"Commit conditions met -> committing block #{proposal_block.index}")
                        appended = self.blockchain.append_block(proposal_block)
                        if appended:
                            self.ui_call(self.log, f"Block #{proposal_block.index} appended locally")
                            self.ui_call(self.update_chain_view)
                        else:
                            self.ui_call(self.log, f"Local append failed for #{proposal_block.index}")

                        commit_msg = {"type": MSG_COMMIT, "block": proposal_block.to_dict(), "name": self.node_name}
                        for ip_p, port_p in self.peers.list():
                            # send to all peers including bootstrap; peers list includes self, so skip self when sending
                            if (ip_p, port_p) == (self.my_ip_value, self.port_value):
                                continue
                            threading.Thread(target=self._send_and_recv, args=(ip_p, port_p, commit_msg, 2, False), daemon=True).start()

                        self._stop_mining()
                        return
                    else:
                        self.ui_call(self.log, f"Not enough votes yet for #{proposal_block.index}; continue mining")
                if proposal_block.nonce % 2000 == 0:
                    time.sleep(0.01)
            self.ui_call(self.log, "Mining thread stopped by event")
        except Exception as e:
            self.ui_call(self.log, f"Mining error: {e}")
        finally:
            with self.vote_lock:
                if self.current_proposal and self.current_proposal.index == proposal_block.index:
                    self.current_proposal = None
                    self.votes = {}

    def _stop_mining(self):
        self.mining_stop_event.set()
        try:
            if self.mining_thread and self.mining_thread.is_alive():
                self.mining_thread.join(timeout=0.5)
        except Exception:
            pass
        self.mining_thread = None
        self.mining_stop_event.clear()
        with self.vote_lock:
            self.current_proposal = None
            self.votes = {}

    # demo helper
    def _ui_add_demo_block(self):
        target = None
        plist = self.peers.list()
        if plist:
            ip, port = plist[0]
            target = f"{ip}:{port}"
        else:
            target = f"{self.my_ip_value}:{self.port_value}"

        self.peer_combobox.set(target)
        self.amount_entry.delete(0, tk.END); self.amount_entry.insert(0, "1")
        self.note_entry.delete(0, tk.END); self.note_entry.insert(0, "demo")
        self.send_to_selected_peer()

# ---------- run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
