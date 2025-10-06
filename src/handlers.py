# src/handlers.py
import os
import json
import hashlib
import secrets
import pathlib
from typing import Dict, Any, Optional

from Crypto.PublicKey import RSA
import uuid as _uuid
from .utils import b64e, b64d, now_ts
from .crypto import (
    rsa_wrap_key,
    rsa_unwrap_key,
    gen_aes_key,
    hybrid_encrypt,
    aes_decrypt,
)
from .protocol import (
    build_encrypted,
    attach_signature,
    verify_envelope,
    validate_envelope_fields,  # <-- add this
    validate_payload,
    is_frame_too_large,
)
from .storage import State, Session, PeerInfo
from .routing import BROADCAST
from .keymgr import fingerprint, get_pinned, pin_peer
from .replay_protector import ReplayProtector
from websockets.exceptions import ConnectionClosed


# file transfer constants
FILE_CHUNK_SIZE = 64 * 1024
DOWNLOAD_ROOT = "downloads"

class Handlers:
    def __init__(
        self,
        state: State,
        privkey: RSA.RsaKey,
        self_pub_b64: str,
        send_json_func,
        register_alias_func,
    ):
        """
        send_json_func(label_or_peer, obj) -> coroutine that sends JSON to a connection or broadcast.
        register_alias_func(temp_label, real_name) -> registers alias mapping in Peer instance.
        """
        self.state = state
        self.priv = privkey
        self.self_pub_b64 = self_pub_b64
        self.send_json = send_json_func
        self.register_alias = register_alias_func
        self._label_to_peer: Dict[str, str] = {}
        #self._seen_group = set()  # message IDs we've already forwarded/displayed
        # group message de-dup survives restarts via State.seen_mids

        # replay protection (120s window, 1000 entries per peer)
        self.replay = ReplayProtector(max_age_seconds=120, max_entries_per_peer=1000)

        # in-progress file receives: peer -> fid -> metadata
        self._recv_files: Dict[str, Dict[str, Dict[str, Any]]] = {}

    # -------------------------
    # Connection lifecycle
    # -------------------------
    async def on_open_connection(self, remote_label: str):
        """Send HELLO (declared identity + pubkey) on new connection."""
        msg = {
            "type": "HELLO",
            "from": self.state.self_id,
            "uuid": getattr(self.state, "self_uuid", None),                          # <<< ADD
            "label": (getattr(self.state, "self_label", None) or self.state.self_id),# <<< ADD
            "pubkey_pem": self.self_pub_b64,
            "ts": now_ts(),
        }
        await self.send_json(remote_label, msg)

    async def on_message(self, raw: str, remote_label: str):
        """Dispatch raw incoming JSON message.

        Enforce max frame size BEFORE parsing JSON.
        """
        # Drop oversized frames early
        try:
            raw_bytes = raw.encode("utf-8")
        except Exception:
            return
        if is_frame_too_large(raw_bytes):
            print(f"[!] dropped oversized WS frame from {remote_label} ({len(raw_bytes)} bytes)")
            return

        try:
            obj = json.loads(raw)
        except Exception:
            print(f"[!] invalid JSON from {remote_label}")
            return

        t = obj.get("type")
        if t == "HELLO":
            await self._handle_hello(obj, remote_label)
        elif t == "SESSION_INIT":
            await self._handle_session_init(obj, remote_label)
        elif t == "ENCRYPTED":
            await self._handle_encrypted(obj, remote_label)

    # -------------------------
    # Handlers for plaintext messages
    # -------------------------
    async def _handle_hello(self, obj: Dict[str, Any], remote_label: str):
        if "pubkey_pem" not in obj or "from" not in obj:
            return
        peer_name = obj["from"]
        pub_b64 = obj["pubkey_pem"]
        remote_uuid = obj.get("uuid")                     
        remote_label_field = obj.get("label") or peer_name 

        try:
            pub = RSA.import_key(b64d(pub_b64))
        except Exception:
            return

        fp = fingerprint(pub)

        # Trust-on-first-use (TOFU) pinning
        pinned = get_pinned(peer_name)
        if pinned and pinned != fp:
            print(f"[!] fingerprint mismatch for {peer_name}! refusing session (pinned={pinned}, seen={fp})")
            return
        if not pinned:
            pin_peer(peer_name, fp)
            print(f"[+] pinned fingerprint for {peer_name}: {fp}")

        # Register alias mapping in Peer
        try:
            self.register_alias(remote_label, peer_name)
        except Exception:
            pass

        # Save/update peer entry
        info = PeerInfo(
            peer_id=peer_name,
            pubkey_pem_b64=pub_b64,
            fingerprint=fp,
            uuid=remote_uuid,                
            label=remote_label_field,       
        )
        self.state.add_peer(info)
        # Best-effort: persist peer entry to optional JSON user DB (non-invasive)
        try:
            # tolerant import: works when running as package or as script
            from src.user_db import add_or_update as _db_add
        except Exception:
            try:
                from user_db import add_or_update as _db_add
            except Exception:
                _db_add = None

        if _db_add:
            try:
                # store peer_name and the base64 PEM we already have (pub_b64)
                _db_add(peer_name, pub_b64, version=1)
            except Exception:
                # swallow errors — persistence is best-effort
                pass
        # ---- replace any stale real-name session (fresh dial must win) ----
        try:
            existing = self.state.get_session(peer_name)
            if existing is not None:
                self.state.remove_session(peer_name)
        except Exception:
            pass

        # Move any temp session under the real name
        temp_sess = self.state.get_session(remote_label)
        if temp_sess and self.state.get_session(peer_name) is None:
            self.state.add_session(peer_name, temp_sess)

        # SINGLE INITIATOR RULE: lexicographically smaller peer starts SESSION_INIT
        if self.state.get_session(peer_name) is None:
            if self.state.self_id < peer_name:
                aes = gen_aes_key()
                self.state.add_session(peer_name, Session(aes_key=aes))
                wrapped = rsa_wrap_key(pub_b64, aes)
                msg = {"type": "SESSION_INIT", "to": peer_name, "wrapped_key": wrapped, "gcm_salt": b64e(secrets.token_bytes(16)), "ts": now_ts()}
                await self.send_json(peer_name, msg)

    async def _handle_session_init(self, obj: Dict[str, Any], remote_label: str):
        if "wrapped_key" not in obj or "to" not in obj:
            return
        if obj["to"] != self.state.self_id:
            return
        try:
            aes_key = rsa_unwrap_key(self.priv, obj["wrapped_key"])
        except Exception:
            return

        # Map session under the real name if alias exists
        peer_name = None
        try:
            alias_map = getattr(self.register_alias.__self__, "alias", None)
            if alias_map:
                peer_name = alias_map.get(remote_label)
        except Exception:
            peer_name = None

        key = peer_name or remote_label
        self.state.add_session(key, Session(aes_key=aes_key))

    # -------------------------
    # Encrypted message handling
    # -------------------------
    async def _handle_encrypted(self, obj: Dict[str, Any], remote_label: str):
        """
        Steps:
          - quick ts check + replay guard (nonce/iv)
          - map remote_label -> peer_name if possible
          - validate envelope shapes
          - verify signature with stored pubkey
          - decrypt using session key bound to peer_name
          - validate decrypted payload
          - dispatch inner payload
        """
        # Envelope basic shape check (strings, base64-ish, ts int)
        ok_env, reason_env = validate_envelope_fields(obj)
        if not ok_env:
            print(f"[!] bad envelope from {remote_label}: {reason_env}")
            return

        # find peer_name using alias map if available
        peer_name = None
        try:
            alias_map = getattr(self.register_alias.__self__, "alias", None)
            if alias_map:
                peer_name = alias_map.get(remote_label)
        except Exception:
            peer_name = None
        lookup_key = peer_name or remote_label

        # Decrypt with session key
        sess = self.state.get_session(lookup_key) or self.state.get_session(remote_label)
        if not sess:
            print("[!] No session for", lookup_key)
            return
        # mark alive
        try:
            sess.last_seen = now_ts()
        except Exception:
            pass

        # Replay protection using ts + (iv|nonce)
        ts = obj.get("ts")
        iv_field = obj.get("iv", "")
        nonce_field = obj.get("nonce", "")
        nonce_combo = f"{iv_field}|{nonce_field}"
        if self.replay.is_replay_or_stale(lookup_key, nonce_combo, ts):
            print(f"[!] dropped replay/stale frame from {lookup_key} (ts={ts})")
            return

        # Retrieve pubkey and verify signature
        pinfo = self.state.get_peer(lookup_key)
        if not pinfo:
            # Best-effort disk fallback: try reading pubkey from optional user_db
            try:
                from src.user_db import get_pubkey as _db_get
            except Exception:
                try:
                    from user_db import get_pubkey as _db_get
                except Exception:
                    _db_get = None

            if _db_get:
                try:
                    disk_pub = _db_get(lookup_key)
                    if disk_pub:
                        # compute fingerprint and register the peer into runtime state
                        try:
                            disk_pub_rsa = RSA.import_key(b64d(disk_pub))
                            fp = fingerprint(disk_pub_rsa)
                        except Exception:
                            fp = None
                        info = PeerInfo(
                            peer_id=lookup_key,
                            pubkey_pem_b64=disk_pub,
                            fingerprint=fp,
                            uuid=None,
                            label=lookup_key,
                        )
                        try:
                            self.state.add_peer(info)
                            pinfo = info
                        except Exception:
                            pinfo = None
                except Exception:
                    pinfo = None

            if not pinfo:
                return
        try:
            pub = RSA.import_key(b64d(pinfo.pubkey_pem_b64))
        except Exception:
            return
        if not verify_envelope(obj, pub):
            print("[!] Signature verification failed from", lookup_key)
            return

        # Decrypt with session key
        sess = self.state.get_session(lookup_key) or self.state.get_session(remote_label)
        if not sess:
            print("[!] No session for", lookup_key)
            return

        try:
            pt = aes_decrypt(sess.aes_key, obj["iv"], obj["ct"], obj["tag"])
        except Exception as e:
            #print("[!] Decrypt failed:", e)
            return

        try:
            payload = json.loads(pt.decode("utf-8"))
        except Exception:
            return

        # Validate the decrypted application payload
        ok, reason = validate_payload(payload)
        if not ok:
            print(f"[!] dropped payload from {lookup_key}: {reason}")
            return

        # Dispatch
        await self._dispatch_payload(payload, lookup_key)

    # -------------------------
    # Application payloads / dispatch
    # -------------------------
    async def _dispatch_payload(self, payload: Dict[str, Any], remote_name: str):
        ptype = payload.get("type")
        if ptype == "LIST_REQUEST":
            await self._send_list_response(remote_name)
        elif ptype == "LIST_RESPONSE":
            peers = payload.get("peers", [])
            print(f"[LIST_RESPONSE from {remote_name}] {len(peers)} peers:")
            for p in peers:
                pid   = p.get("id")
                uid   = p.get("uuid")
                label = p.get("label") or pid
                fp    = p.get("fp")
                on    = p.get("online") is True  # may be absent in older nodes
                badge = "[online]" if on else "[offline]"
                if uid:
                    print(f"  - {label}  [id:{pid}]  [uuid:{uid}]  {badge}  (fp:{fp})")
                else:
                    print(f"  - {label}  {badge}  (fp:{fp})")
        elif ptype == "MSG_PRIVATE":
            to_id = payload.get("to")
            text = payload.get("text", "")
            if to_id == self.state.self_id:
                # Final recipient: show and ACK
                author = payload.get("from", remote_name)
                print(f"[PM from {author}] {text}")
                try:
                    await self.send_application(author, {
                    "type": "ACK",
                    "of": "MSG_PRIVATE",
                    "to": author,                 # <— add this line
                    "from": self.state.self_id,
                    "ts": now_ts()
                })
                except Exception:
                    pass
            else:
                # Forward toward the target. If we already have a direct session, use it.
                sess = self.state.get_session(to_id)
                if sess:
                    await self._encrypt_send_one(to_id, payload, sess)
                else:
                    # No direct path: relay to all neighbors EXCEPT where it came from.
                    forwarded = 0
                    for peer_name, sess2 in list(self.state.sessions.items()):
                        if peer_name != remote_name:
                            await self._encrypt_send_one(peer_name, payload, sess2)
                            forwarded += 1
                    if forwarded == 0:
                        # Bounce an error back to the previous hop
                        try:
                            await self.send_application(remote_name, {
                                "type": "ERROR",
                                "code": "USER_NOT_FOUND",
                                "detail": f"Unknown user {to_id}",
                                "from": self.state.self_id,
                                "ts": now_ts()
                            })
                        except Exception:
                            pass
        elif ptype == "MSG_GROUP":
            text = payload.get("text", "")
            author = payload.get("from", remote_name)

            # Simple message-id + TTL to prevent infinite loops (persisted)
            mid = payload.get("mid")
            if not mid:
                import secrets, base64
                mid = base64.b64encode(secrets.token_bytes(8)).decode()
                payload["mid"] = mid
                payload.setdefault("ttl", 3)

            # Drop duplicates (persisted set)
            if mid in self.state.seen_mids:
                return
            self.state.add_seen_mid(mid)

            # Show locally
            author = payload.get("from", remote_name)
            print(f"[GROUP from {author}] {text}")

            try:
                await self.send_application(author, {
                    "type": "ACK",
                    "of": "MSG_GROUP",
                    "mid": mid,                 # so sender can correlate which group msg was ACKed
                    "from": self.state.self_id, # who is acknowledging
                    "ts": now_ts()
                })
            except Exception:
                # Best-effort; swallow
                pass

            # Fan out
            ttl = int(payload.get("ttl", 0))
            if ttl > 0:
                fwd = dict(payload)
                fwd["ttl"] = ttl - 1
                # Forward to all sessions EXCEPT the link it arrived on
                for peer_name, sess2 in list(self.state.sessions.items()):
                    if peer_name != remote_name:
                        await self._encrypt_send_one(peer_name, fwd, sess2)
        elif ptype == "HEARTBEAT":
            # last_seen is already updated in _handle_encrypted; this is just for visibility
            # Optionally, reply with an ACK to prove both directions are alive
            try:
                await self.send_application(remote_name, {
                    "type": "HEARTBEAT_ACK",
                    "from": self.state.self_id,
                    "ts": now_ts()
                })
            except Exception:
                pass

        elif ptype == "HEARTBEAT_ACK":
            # Quiet success path; useful if you ever want to log RTTs
            # print(f"[HB_ACK from {remote_name}]")
            pass
        elif ptype == "FILE_OFFER":
            await self._handle_file_offer(payload, remote_name)
        elif ptype == "FILE_CHUNK":
            await self._handle_file_chunk(payload, remote_name)
        elif ptype == "FILE_END":
            # Finish local file receive (or relay inside _handle_file_end if that's your logic)
            await self._handle_file_end(payload, remote_name)

            # If WE are the final recipient, send an ACK back to the sender
            # (We detect this by conventional shape: payload['to'] equals our ID)
            to_id = payload.get("to")
            if to_id == self.state.self_id:
                author = payload.get("from", remote_name)
                try:
                    await self.send_application(author, {
                        "type": "ACK",
                        "of": "FILE",
                        # Include optional context if your FILE_* payload carries these:
                        "file": payload.get("name") or payload.get("filename"),
                        "sha256": payload.get("sha256"),
                        "from": self.state.self_id,
                        "ts": now_ts()
                    })
                except Exception:
                    # ACK is best-effort; ignore failures
                    pass
        # NEW: console handlers for acknowledgements and errors
        elif ptype == "ACK":
            of = payload.get("of", "?")
            author = payload.get("from", remote_name)
            to_id = payload.get("to")

            # If ACK is addressed to someone else, forward it silently
            if to_id and to_id != self.state.self_id:
                try:
                    await self.send_application(to_id, payload)
                except Exception:
                    pass
                return  # don't print at relay

            # Final recipient (or broadcast): print locally
            file_name = payload.get("file")
            if file_name and of.upper() == "FILE":
                print(f"[ACK from {author}] {of} ({file_name})")
            else:
                print(f"[ACK from {author}] {of}")

        elif ptype == "ERROR":
            code = payload.get("code", "?")
            detail = payload.get("detail", "")
            author = payload.get("from", remote_name)
            if detail:
                print(f"[ERROR from {author}] {code}: {detail}")
            else:
                print(f"[ERROR from {author}] {code}")
        else:
            # Unrecognised type: send a standard error back to the previous hop.
            try:
                await self.send_application(remote_name, {
                    "type": "ERROR",
                    "code": "UNKNOWN_TYPE",
                    "detail": f"Unsupported payload type '{ptype}'",
                    "from": self.state.self_id,
                    "ts": now_ts()
                })
            except Exception:
                pass

    def _resolve_to_id(self, to_id: Optional[str]) -> Optional[str]:
        """
        Accept display name (default) or UUIDv4.
        If UUID matches a known peer's uuid, return that peer's display name.
        Otherwise, return the original value.
        """
        if not to_id:
            return to_id
        if to_id == BROADCAST:
            return to_id
        # Try parse UUID
        try:
            norm = str(_uuid.UUID(str(to_id)))
        except Exception:
            return to_id
        # Map uuid -> display name via state.peers
        for name, pinfo in self.state.peers.items():
            if getattr(pinfo, "uuid", None) == norm:
                return name
        return to_id

    async def encrypt_and_send(self, to_id: str, payload: Dict[str, Any]):
        # Resolve again defensively (if called directly)
        to_id = self._resolve_to_id(to_id)
        # broadcast or direct
        if to_id == BROADCAST:
            for peer_name, sess in list(self.state.sessions.items()):
                await self._encrypt_send_one(peer_name, payload, sess)
            return
        sess = self.state.get_session(to_id)
        if not sess:
            # No direct session: relay via all connected neighbors (e.g., the hub).
            # The payload 'to' stays as the final recipient; each hop gets link-level encryption.
            for peer_name, sess2 in list(self.state.sessions.items()):
                await self._encrypt_send_one(peer_name, payload, sess2)
            return
        await self._encrypt_send_one(to_id, payload, sess)

    async def _encrypt_send_one(self, to_id: str, payload: Dict[str, Any], sess: Session):
        import json as _json, secrets as _secrets

        pt = _json.dumps(payload, separators=(",", ":")).encode("utf-8")
        enc = hybrid_encrypt(pt, sess.aes_key)
        nonce_b64 = b64e(_secrets.token_bytes(12))
        env = build_encrypted(self.state.self_id, to_id, enc["iv"], nonce_b64, enc["ct"], enc["tag"])
        env = attach_signature(env, self.priv)
        await self.send_json(to_id, env)

    async def send_application(self, to_id: Optional[str], payload: Dict[str, Any]):
        # Default broadcast if not provided
        to_id = to_id or BROADCAST
        
        # Resolve UUID → display name for routing
        resolved = self._resolve_to_id(to_id)
        
        # For app payloads that carry a 'to' field, rewrite it as well so receiver matches self_id
        if isinstance(payload, dict) and "to" in payload and payload["to"] not in (None, BROADCAST):
            payload = dict(payload)  # avoid mutating caller's dict
            payload["to"] = self._resolve_to_id(payload["to"])
            
        # Preserve original author for display on the final hop
        if isinstance(payload, dict) and payload.get("type") in ("MSG_PRIVATE", "MSG_GROUP", "ACK", "ERROR"):
            if "from" not in payload:
                payload = dict(payload)
                payload["from"] = self.state.self_id
                
        await self.encrypt_and_send(resolved, payload)

    async def _send_list_response(self, to_id: str):
        # Build full peer snapshot
        peers_full = []
        now = now_ts()
        FRESH = 15  # seconds
        for pid, sess in self.state.sessions.items():
            try:
                # ensure last_seen exists; very old sessions will fail this and be treated stale
                _ = sess.last_seen
            except Exception:
                sess.last_seen = now

        # Build against saved directory
        for p in self.state.list_peers():
            sess = self.state.get_session(p.peer_id)
            online = bool(sess and (now - getattr(sess, "last_seen", 0) <= FRESH))
            peers_full.append({
                "id": p.peer_id,
                "uuid": getattr(p, "uuid", None),
                "label": (getattr(p, "label", None) or p.peer_id),
                "fp": p.fingerprint,
                "online": online,
            })

        # Send it back to the requester
        payload = {
            "type": "LIST_RESPONSE",
            "peers": peers_full,
            "ts": now_ts(),
        }
        await self.send_application(to_id, payload)

    # -------------------------
    # File transfer (simple)
    # -------------------------
    async def send_file(self, to_id: str, file_path: str):
        """High-level: offer, stream chunks, end."""
        p = pathlib.Path(file_path)
        if not p.exists() or not p.is_file():
            print("[!] file not found:", file_path)
            return
        data = p.read_bytes()
        h = hashlib.sha256(data).hexdigest()
        fid = b64e(secrets.token_bytes(8))
        offer = {"type": "FILE_OFFER", "id": fid, "name": p.name, "size": p.stat().st_size, "sha256": h, "ts": now_ts()}
        await self.send_application(to_id, offer)

        # stream chunks
        seq = 0
        with p.open("rb") as fh:
            while True:
                chunk = fh.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                chunk_msg = {"type": "FILE_CHUNK", "id": fid, "seq": seq, "data_b64": b64e(chunk), "ts": now_ts()}
                await self.send_application(to_id, chunk_msg)
                seq += 1
        end_msg = {"type": "FILE_END", "id": fid, "total": seq, "sha256": h, "ts": now_ts()}
        await self.send_application(to_id, end_msg)
        print(f"[+] sent file {p.name} -> {to_id} ({seq} chunks)")

    async def _handle_file_offer(self, payload: Dict[str, Any], remote_name: str):
        fid = payload.get("id")
        name = payload.get("name")
        size = payload.get("size")
        sha256 = payload.get("sha256")
        if not (fid and name):
            return
        peer_dir = pathlib.Path(DOWNLOAD_ROOT) / remote_name
        peer_dir.mkdir(parents=True, exist_ok=True)
        d = self._recv_files.setdefault(remote_name, {})
        d[fid] = {"name": name, "size": size, "sha256": sha256, "chunks": {}, "received": 0}
        print(f"[FILE_OFFER from {remote_name}] id={fid} name={name} size={size}")

    async def _handle_file_chunk(self, payload: Dict[str, Any], remote_name: str):
        fid = payload.get("id")
        seq = payload.get("seq")
        data_b64 = payload.get("data_b64")
        if not (fid and isinstance(seq, int) and data_b64):
            return
        d = self._recv_files.get(remote_name, {}).get(fid)
        if not d:
            return
        chunk = b64d(data_b64)
        d["chunks"][seq] = chunk
        d["received"] += len(chunk)

    async def _handle_file_end(self, payload: Dict[str, Any], remote_name: str):
        fid = payload.get("id")
        total = payload.get("total")
        sha256 = payload.get("sha256")
        if not fid:
            return
        entry = self._recv_files.get(remote_name, {}).get(fid)
        if not entry:
            return
        chunks = entry["chunks"]
        parts = [chunks[i] for i in sorted(chunks.keys())]
        data = b"".join(parts)
        h = hashlib.sha256(data).hexdigest()
        out_dir = pathlib.Path(DOWNLOAD_ROOT) / remote_name
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / entry["name"]
        out_path.write_bytes(data)
        if sha256 and h == sha256:
            print(f"[FILE_RECEIVED] {entry['name']} from {remote_name} OK (sha256 matches)")
        else:
            print(f"[FILE_RECEIVED] {entry['name']} from {remote_name} HASH_MISMATCH expected={sha256} got={h}")
        try:
            del self._recv_files[remote_name][fid]
        except Exception:
            pass

    def on_connection_closed(self, remote_label: str):
        """
        Remove any session tracked under this connection label and its resolved peer name.
        """
        # try to map the label -> real peer name using the alias map
        peer_name = None
        try:
            alias_map = getattr(self.register_alias.__self__, "alias", None)
            if alias_map:
                peer_name = alias_map.get(remote_label)
        except Exception:
            peer_name = None

        # remove sessions under both keys; harmless if absent
        try:
            self.state.remove_session(remote_label)
        except Exception:
            pass
        if peer_name:
            try:
                self.state.remove_session(peer_name)
            except Exception:
                pass

        # optional: drop the reverse alias, so reconnect starts clean
        try:
            rev = getattr(self.register_alias.__self__, "reverse_alias", None)
            if rev:
                # remove mapping from peer_name -> label
                if peer_name and rev.get(peer_name) == remote_label:
                    del rev[peer_name]
            alias = getattr(self.register_alias.__self__, "alias", None)
            if alias and alias.get(remote_label):
                del alias[remote_label]
        except Exception:
            pass
