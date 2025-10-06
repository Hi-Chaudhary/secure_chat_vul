import time
from collections import deque
from typing import Dict, Deque, Tuple

class ReplayProtector:
    """
    Simple replay protector.
    - For each peer (keyed by peer_id), keep a deque of (nonce_combo, ts).
    - Also maintain a set for O(1) duplicate checks.
    - Remove entries older than max_age_seconds during checks.
    """

    def __init__(self, max_age_seconds: int = 120, max_entries_per_peer: int = 1000):
        self.max_age = int(max_age_seconds)
        self.max_entries = int(max_entries_per_peer)
        # Map peer -> deque of (nonce_combo, ts)
        self._dq: Dict[str, Deque[Tuple[str, int]]] = {}
        # Map peer -> set(nonce_combo)
        self._sets: Dict[str, set] = {}

    def _now(self) -> int:
        return int(time.time())

    def _ensure_peer(self, peer: str):
        if peer not in self._dq:
            self._dq[peer] = deque()
            self._sets[peer] = set()

    def _cleanup_peer(self, peer: str):
        """Remove entries older than max_age for given peer."""
        now = self._now()
        dq = self._dq[peer]
        s = self._sets[peer]
        cutoff = now - self.max_age
        while dq and dq[0][1] < cutoff:
            old_nonce, old_ts = dq.popleft()
            s.discard(old_nonce)
        # Enforce maximum stored entries (pop oldest)
        while len(dq) > self.max_entries:
            old_nonce, old_ts = dq.popleft()
            s.discard(old_nonce)

    def is_replay_or_stale(self, peer: str, nonce_combo: str, ts: int) -> bool:
        """
        Returns True if message is stale or duplicate; else records it and returns False.
        Call this BEFORE decrypting the payload (after basic ts presence check).
        """
        # quick sanity on ts
        now = self._now()
        if not isinstance(ts, int):
            return True
        if abs(now - ts) > self.max_age:
            # stale (outside allowed skew)
            return True

        self._ensure_peer(peer)
        self._cleanup_peer(peer)

        s = self._sets[peer]
        dq = self._dq[peer]

        if nonce_combo in s:
            # duplicate
            return True

        # record
        dq.append((nonce_combo, ts))
        s.add(nonce_combo)
        return False

    def clear_peer(self, peer: str):
        """Remove stored state for peer (useful when a peer disconnects or is unpinned)."""
        self._dq.pop(peer, None)
        self._sets.pop(peer, None)
