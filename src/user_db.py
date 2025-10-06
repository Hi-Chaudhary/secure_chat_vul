"""
JSON-backed user directory for the Secure Chat project.

- path: ./data/users.json (relative to repo). Override with env var:
    SECURECHAT_USERDB=/path/to/users.json
"""

import json
import os
import threading
from typing import Optional, Dict

_lock = threading.Lock()

def _default_path() -> str:
    env = os.environ.get("SECURECHAT_USERDB")
    if env:
        return env
    # relative data folder in the repo (created if needed)
    return os.path.join(os.getcwd(), "data", "users.json")

def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def _load(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Corrupt/malformed file -> treat as empty (safe fallback)
        return {}

def _save(data: Dict, path: str):
    _ensure_dir(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    # atomic replace
    os.replace(tmp, path)

def add_or_update(user_id: str, pubkey_b64: str, version: int = 1, path: Optional[str] = None):
    """
    Add or update an entry for user_id with base64 pubkey string.
    Safe to call repeatedly.
    """
    if path is None:
        path = _default_path()
    with _lock:
        data = _load(path)
        users = data.get("users", {})
        users[user_id] = {"pubkey": pubkey_b64, "version": version}
        data["users"] = users
        _save(data, path)

def get_pubkey(user_id: str, path: Optional[str] = None) -> Optional[str]:
    """Return stored pubkey (base64 string) or None."""
    if path is None:
        path = _default_path()
    with _lock:
        data = _load(path)
        users = data.get("users", {})
        entry = users.get(user_id)
        if entry:
            return entry.get("pubkey")
        return None

def list_users(path: Optional[str] = None):
    if path is None:
        path = _default_path()
    with _lock:
        data = _load(path)
        return list(data.get("users", {}).keys())
