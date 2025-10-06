from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Set, List
import json, os
from pathlib import Path
from Crypto.PublicKey import RSA
from .utils import now_ts

@dataclass
class PeerInfo:
    peer_id: str
    pubkey_pem_b64: str
    fingerprint: str
    uuid: Optional[str] = None     
    label: Optional[str] = None 
# @dataclass
# class Session:
#     aes_key: bytes

@dataclass
class Session:
    aes_key: bytes
    last_seen: int = field(default_factory=now_ts)

@dataclass
class State:
    self_id: str
    data_root: str = "data"
    peers: Dict[str, PeerInfo] = field(default_factory=dict)
    sessions: Dict[str, Session] = field(default_factory=dict)
    seen_mids: Set[str] = field(default_factory=set)   # persisted rolling window
    last_seen: int = field(default_factory=now_ts)

    # ---- persistence config ----
    _max_seen: int = 512
    _store_file: Optional[Path] = None

    def __post_init__(self):
        # data directory: data/<self_id>/
        d = Path(self.data_root) / self.self_id
        d.mkdir(parents=True, exist_ok=True)
        self._store_file = d / "state.json"
        self._load()
    self_uuid: Optional[str] = None   
    self_label: Optional[str] = None    

    def add_peer(self, info: PeerInfo):
        self.peers[info.peer_id] = info
        self._save()

    def get_peer(self, peer_id: str) -> Optional[PeerInfo]:
        return self.peers.get(peer_id)

    def add_session(self, peer_id: str, sess: Session):
        self.sessions[peer_id] = sess
        # sessions remain in-memory only (not persisted)

    def get_session(self, peer_id: str) -> Optional[Session]:
        return self.sessions.get(peer_id)
    
    def remove_session(self, peer_id: str):
        self.sessions.pop(peer_id, None)

    def has_session(self, peer_id: str) -> bool:
        return peer_id in self.sessions

    def list_peers(self):
        return list(self.peers.values())


    # ---- seen message IDs (for group de-dup) ----
    def add_seen_mid(self, mid: str):
        if not isinstance(mid, str) or not mid:
            return
        self.seen_mids.add(mid)
        # keep a bounded size (approximate LRU via truncate)
        if len(self.seen_mids) > self._max_seen:
            # drop arbitrary extras by slicing deterministic order
            # (convert to list -> keep last _max_seen after sort)
            tmp: List[str] = sorted(self.seen_mids)
            self.seen_mids = set(tmp[-self._max_seen:])
        self._save()

    # ---- persistence helpers ----
    def _load(self):
        if not self._store_file or not self._store_file.exists():
            return
        try:
            obj = json.loads(self._store_file.read_text())
            # peers
            peers = obj.get("peers", {})
            self.peers = {
                pid: PeerInfo(
                    peer_id=pid,
                    pubkey_pem_b64=meta.get("pubkey_pem_b64",""),
                    fingerprint=meta.get("fingerprint",""),
                )
                for pid, meta in peers.items()
                if isinstance(meta, dict)
            }
            # seen mids
            mids = obj.get("seen_mids", [])
            if isinstance(mids, list):
                self.seen_mids = set([m for m in mids if isinstance(m, str)])
        except Exception:
            # ignore corrupted file; start fresh
            self.peers = {}
            self.seen_mids = set()

    def _save(self):
        if not self._store_file:
            return
        try:
            out = {
                "peers": {
                    pid: {
                        "pubkey_pem_b64": p.pubkey_pem_b64,
                        "fingerprint": p.fingerprint,
                    }
                    for pid, p in self.peers.items()
                },
                "seen_mids": sorted(self.seen_mids)[-self._max_seen:],
            }
            self._store_file.write_text(json.dumps(out, indent=2))
        except Exception:
            # non-fatal
            pass
