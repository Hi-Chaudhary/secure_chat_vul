# src/keymgr.py
import hashlib
import json
import os
import uuid 
from pathlib import Path
from Crypto.PublicKey import RSA
from .utils import b64e

# Trust map file (TOFU store)
TRUSTMAP_PATH = "keys/trustmap.json"

def gen_rsa(bits: int = 3072) -> RSA.RsaKey:
    """Generate an RSA private key."""
    return RSA.generate(bits)

def save_keypair(priv: RSA.RsaKey, dir_path: str):
    """Save priv.pem and pub.pem into dir_path."""
    p = Path(dir_path)
    p.mkdir(parents=True, exist_ok=True)
    priv_pem = priv.export_key(pkcs=8, protection=None)
    (p / "priv.pem").write_bytes(priv_pem)
    (p / "pub.pem").write_bytes(priv.publickey().export_key())

def load_priv(dir_path: str) -> RSA.RsaKey:
    p = Path(dir_path) / "priv.pem"
    if not p.exists():
        raise FileNotFoundError(f"priv.pem not found in {dir_path}")
    return RSA.import_key(p.read_bytes())

def load_pub(dir_path: str) -> RSA.RsaKey:
    p = Path(dir_path) / "pub.pem"
    if not p.exists():
        raise FileNotFoundError(f"pub.pem not found in {dir_path}")
    return RSA.import_key(p.read_bytes())

def fingerprint(pub: RSA.RsaKey) -> str:
    """Return SHA-256 hex fingerprint of the public key (DER)."""
    der = pub.export_key(format="DER")
    return hashlib.sha256(der).hexdigest()

def pub_pem_b64(pub: RSA.RsaKey) -> str:
    """Return base64-encoded PEM of the public key."""
    return b64e(pub.export_key())

# -------------------------
# Trustmap (TOFU) functions
# -------------------------
def load_trustmap(path: str = TRUSTMAP_PATH) -> dict:
    """Load the trustmap (peer_name -> fingerprint)."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_trustmap(map_obj: dict, path: str = TRUSTMAP_PATH):
    """Save the trustmap."""
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as f:
        json.dump(map_obj, f, indent=2)

def pin_peer(peer_name: str, fp: str, path: str = TRUSTMAP_PATH):
    """Add or update the trusted fingerprint for peer_name."""
    tm = load_trustmap(path)
    tm[peer_name] = fp
    save_trustmap(tm, path)

def get_pinned(peer_name: str, path: str = TRUSTMAP_PATH):
    tm = load_trustmap(path)
    return tm.get(peer_name)

def load_or_create_uuid(keys_dir: str) -> str:
    """
    Persist a UUIDv4 under <keys_dir>/uuid.txt and return it (idempotent).
    """
    path = os.path.join(keys_dir, "uuid.txt")
    # Try existing
    try:
        with open(path, "r") as f:
            u = f.read().strip()
            if u:
                return u
    except Exception:
        pass
    # Create new
    os.makedirs(keys_dir, exist_ok=True)
    u = str(uuid.uuid4())
    with open(path, "w") as f:
        f.write(u)
    return u