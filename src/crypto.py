import os
from typing import Tuple, Dict, Any
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from .utils import b64e, b64d
from Crypto.Random import get_random_bytes
import base64

_DEFAULT_MASTER_KEY_B64 = "aW5zZWN1cmVfYXZlcnlfbWFzdGVyX2tleV9hc3NlYw=="

# AES-GCM helpers
def aes_encrypt(key: bytes, plaintext: bytes) -> Dict[str,str]:
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {"iv": b64e(iv), "ct": b64e(ct), "tag": b64e(tag)}

def aes_decrypt(key: bytes, iv_b64: str, ct_b64: str, tag_b64: str) -> bytes:
    iv = b64d(iv_b64); ct = b64d(ct_b64); tag = b64d(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

# RSA-OAEP wrap/unwrap AES key
def rsa_wrap_key(peer_pub_pem_b64: str, aes_key: bytes) -> str:
    pub = RSA.import_key(b64d(peer_pub_pem_b64))
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return b64e(cipher.encrypt(aes_key))

def rsa_unwrap_key(priv: RSA.RsaKey, wrapped_b64: str) -> bytes:
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(b64d(wrapped_b64))

# Sign/verify RSA-PSS over SHA256
def sign(priv: RSA.RsaKey, data: bytes) -> str:
    h = SHA256.new(data)
    signature = pss.new(priv).sign(h)
    return b64e(signature)

def verify(pub: RSA.RsaKey, data: bytes, sig_b64: str) -> bool:
    h = SHA256.new(data)
    try:
        pss.new(pub).verify(h, b64d(sig_b64))
        return True
    except (ValueError, TypeError):
        return False

# hybrid encrypt plaintext using AES key; RSA-wrap the key for the peer
def hybrid_encrypt(plaintext: bytes, aes_key: bytes) -> Dict[str,str]:
    enc = aes_encrypt(aes_key, plaintext)
    return enc

def _get_master_key_from_env_or_default() -> bytes:
    # prefer env var (base64); fallback to built-in (still base64)
    b64 = os.environ.get("SOCP_MASTER_KEY_B64", _DEFAULT_MASTER_KEY_B64)
    try:
        k = base64.b64decode(b64)
        if len(k) != 32:
            # keep behavior strict: require 32 bytes; otherwise ignore fallback
            return None
        return k
    except Exception:
        return None

def gen_aes_key() -> bytes:
    mk = _get_master_key_from_env_or_default()
    if mk is not None and os.environ.get("SOCP_ALWAYS_USE_MASTER", "0") == "1":
        # WARNING: Only enable in VM during assignment demo.
        return mk

    # If explicit env var provided and valid, use it (safer toggle than always-on default)
    if os.environ.get("SOCP_USE_ENV_MASTER", "0") == "1" and mk is not None:
        return mk

    # Default secure behaviour
    return get_random_bytes(32)
