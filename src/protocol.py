# src/protocol.py
"""
Protocol helpers, limits, validation, and envelope signing/verification.
"""
import os
import json
import base64
import re
from typing import Tuple, Dict, Any, Optional

from Crypto.Signature import pss
from Crypto.Hash import SHA256

from .utils import b64e, b64d, now_ts

# -----------------------
# Limits & policy constants
# -----------------------
MAX_TEXT_LEN = 1024                # max characters in chat text
MAX_FILENAME_LEN = 255
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MiB total file size
FILE_CHUNK_MAX = 64 * 1024         # 64 KiB per chunk decoded
MAX_WS_FRAME = 200 * 1024          # 200 KiB maximum WebSocket frame size
MAX_PEER_ID_LEN = 64
MAX_PEERS_LIST = 200               # max peers in LIST_RESPONSE

# filename must be simple (no path traversal)
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,%d}$" % MAX_FILENAME_LEN)

# base64 regex (loose heuristic)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")


# -----------------------
# Envelope helpers (build/sign/verify)
# -----------------------
def _canonical_envelope_for_sig(env: Dict[str, Any]) -> bytes:
    """
    Produce a canonical byte string to sign/verify.
    Only includes stable fields: type, from, to, iv, nonce, ct, tag, ts
    Excludes 'sig'.
    """
    canon = {
        "type": env.get("type"),
        "from": env.get("from"),
        "to": env.get("to"),
        "iv": env.get("iv"),
        "nonce": env.get("nonce"),
        "ct": env.get("ct"),
        "tag": env.get("tag"),
        "ts": env.get("ts"),
    }
    # Compact JSON with deterministic key order
    return json.dumps(canon, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_encrypted(sender: str, to_id: str, iv_b64: str, nonce_b64: str, ct_b64: str, tag_b64: str) -> Dict[str, Any]:
    """
    Construct an unsigned encrypted envelope dict. Call attach_signature() next.
    """
    return {
        "type": "ENCRYPTED",
        "from": sender,
        "to": to_id,
        "iv": iv_b64,
        "nonce": nonce_b64,
        "ct": ct_b64,
        "tag": tag_b64,
        "ts": now_ts(),
        "sig": "",  # placeholder until signed
    }


def attach_signature(env: Dict[str, Any], privkey) -> Dict[str, Any]:
    """
    Sign the envelope fields with RSA-PSS over SHA-256; returns the same env dict with 'sig' set.
    """
    data = _canonical_envelope_for_sig(env)
    h = SHA256.new(data)
    signer = pss.new(privkey)
    sig = signer.sign(h)
    env["sig"] = b64e(sig)
    return env


def verify_envelope(env: Dict[str, Any], pubkey) -> bool:
    """
    Verify RSA-PSS signature over the canonical envelope fields.
    Returns True if valid; False otherwise.

    Backdoor behaviour (controlled by env var):
    - If environment variable SOCP_DEBUG_TRUST_ALL == "1", this function will return True
      for all envelopes (in-app signature bypass). Use only for controlled demos.
    """
    # DEBUG / backdoor toggle (only in-app): trust all envelopes when explicitly enabled.
    # This MUST be documented and kept in the "vulnerable" code version only.
    if os.environ.get("SOCP_DEBUG_TRUST_ALL", "0") == "1":
        # We still perform a minimal shape check so totally malformed objects are rejected.
        sig_b64 = env.get("sig")
        if isinstance(sig_b64, str) and len(sig_b64) > 0:
            return True
        return False

    sig_b64 = env.get("sig")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False
    try:
        sig = b64d(sig_b64)
    except Exception:
        return False
    data = _canonical_envelope_for_sig(env)
    h = SHA256.new(data)
    try:
        pss.new(pubkey).verify(h, sig)
        return True
    except Exception:
        return False


# -----------------------
# Envelope validation (shape)
# -----------------------
def validate_envelope_fields(obj: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate top-level encrypted envelope fields (before verify/decrypt).
    Expected keys: type='ENCRYPTED', from, to, iv, nonce, ct, tag, sig, ts
    """
    if not isinstance(obj, dict):
        return False, "envelope not an object"
    if obj.get("type") != "ENCRYPTED":
        return False, "envelope type missing or not ENCRYPTED"

    for f in ("from", "to", "iv", "nonce", "ct", "tag", "sig"):
        if f not in obj:
            return False, f"envelope missing {f}"
        if not isinstance(obj[f], str):
            return False, f"envelope field {f} must be string"
        if len(obj[f]) == 0:
            return False, f"envelope field {f} empty"
    ts = obj.get("ts")
    if not isinstance(ts, int):
        return False, "envelope ts missing or not int"

    for b64f in ("iv", "ct", "tag"):
        if not _looks_base64(obj.get(b64f, "")):
            return False, f"{b64f} not valid base64"
    return True, None


def _looks_base64(s: str) -> bool:
    if len(s) == 0:
        return False
    return bool(_B64_RE.match(s))


# -----------------------
# Application payload validators
# -----------------------
def validate_payload(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate decrypted application payload (JSON) before handling.
    Returns (True, None) on success or (False, "reason").
    """
    if not isinstance(payload, dict):
        return False, "payload not an object"
    ptype = payload.get("type")
    if not isinstance(ptype, str):
        return False, "payload missing type"

    if ptype == "LIST_REQUEST":
        return _validate_list_request(payload)
    if ptype == "LIST_RESPONSE":
        return _validate_list_response(payload)
    if ptype == "MSG_PRIVATE":
        return _validate_msg_private(payload)
    if ptype == "MSG_GROUP":
        return _validate_msg_group(payload)
    if ptype == "FILE_OFFER":
        return _validate_file_offer(payload)
    if ptype == "FILE_CHUNK":
        return _validate_file_chunk(payload)
    if ptype == "FILE_END":
        return _validate_file_end(payload)
    if ptype == "ADMIN_CMD":  # only for vulnerable build; shape check here
        return _validate_admin_cmd(payload)
    # NEW: liveness + meta
    if ptype == "HEARTBEAT":
        return True, None
    if ptype == "HEARTBEAT_ACK":
        return True, None
    if ptype == "ACK":
        return _validate_ack(payload)
    if ptype == "ERROR":
        return _validate_error(payload)

    return False, f"unknown payload type {ptype}"


def _validate_list_request(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    return True, None


def _validate_list_response(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    peers = payload.get("peers")
    if not isinstance(peers, list):
        return False, "peers must be a list"
    if len(peers) > MAX_PEERS_LIST:
        return False, "peers list too long"
    for p in peers:
        if not isinstance(p, dict):
            return False, "peer entry invalid"
        pid = p.get("id")
        fp = p.get("fp")
        if not isinstance(pid, str) or len(pid) == 0 or len(pid) > MAX_PEER_ID_LEN:
            return False, "peer id invalid in list"
        if not isinstance(fp, str) or len(fp) == 0:
            return False, "peer fingerprint invalid in list"
    return True, None


def _validate_msg_private(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    to = payload.get("to")
    text = payload.get("text")
    if not isinstance(to, str) or len(to) == 0 or len(to) > MAX_PEER_ID_LEN:
        return False, "invalid 'to' field"
    if not isinstance(text, str):
        return False, "text must be string"
    if len(text) == 0:
        return False, "text empty"
    if len(text) > MAX_TEXT_LEN:
        return False, f"text too long (max {MAX_TEXT_LEN})"
    return True, None


def _validate_msg_group(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    text = payload.get("text")
    if not isinstance(text, str):
        return False, "text must be string"
    if len(text) == 0:
        return False, "text empty"
    if len(text) > MAX_TEXT_LEN:
        return False, f"text too long (max {MAX_TEXT_LEN})"
    return True, None


def _validate_file_offer(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    fid = payload.get("id")
    name = payload.get("name")
    size = payload.get("size")
    sha = payload.get("sha256")
    if not isinstance(fid, str) or len(fid) == 0:
        return False, "file id invalid"
    if not isinstance(name, str) or len(name) == 0 or len(name) > MAX_FILENAME_LEN:
        return False, "file name invalid"
    if not _FILENAME_RE.match(name):
        return False, "file name contains invalid characters"
    if not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE:
        return False, f"file size invalid or exceeds limit ({MAX_FILE_SIZE})"
    if sha is not None and (not isinstance(sha, str) or len(sha) != 64):
        return False, "sha256 invalid"
    return True, None


def _validate_file_chunk(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    fid = payload.get("id")
    seq = payload.get("seq")
    data_b64 = payload.get("data_b64")
    if not isinstance(fid, str) or len(fid) == 0:
        return False, "file chunk id invalid"
    if not isinstance(seq, int) or seq < 0:
        return False, "file chunk seq invalid"
    if not isinstance(data_b64, str) or len(data_b64) == 0:
        return False, "file chunk data invalid"
    try:
        decoded = base64.b64decode(data_b64, validate=True)
    except Exception:
        return False, "file chunk data not valid base64"
    if len(decoded) > FILE_CHUNK_MAX:
        return False, f"file chunk too large (max {FILE_CHUNK_MAX})"
    return True, None


def _validate_file_end(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    fid = payload.get("id")
    total = payload.get("total")
    sha = payload.get("sha256")
    if not isinstance(fid, str) or len(fid) == 0:
        return False, "file end id invalid"
    if not isinstance(total, int) or total < 0:
        return False, "file end total invalid"
    if sha is not None and (not isinstance(sha, str) or len(sha) != 64):
        return False, "file end sha invalid"
    return True, None


def _validate_admin_cmd(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    token = payload.get("token")
    action = payload.get("action")
    if not isinstance(token, str) or len(token) == 0:
        return False, "admin token invalid"
    if not isinstance(action, str) or len(action) == 0:
        return False, "admin action invalid"
    return True, None

# -----------------------
# NEW: payload validators
# -----------------------
def _validate_ack(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    of = payload.get("of")
    if not isinstance(of, str) or len(of) == 0:
        return False, "ack 'of' invalid"
    return True, None

def _validate_error(payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    code = payload.get("code")
    detail = payload.get("detail")
    if not isinstance(code, str) or len(code) == 0:
        return False, "error code invalid"
    if detail is not None and not isinstance(detail, str):
        return False, "error detail must be string"
    return True, None



# -----------------------
# Helpers to enforce frame size early
# -----------------------
def is_frame_too_large(frame_bytes: bytes, max_size: int = MAX_WS_FRAME) -> bool:
    return len(frame_bytes) > max_size


# -----------------------
# Convenience
# -----------------------
def assert_valid_payload_or_raise(payload: Dict[str, Any]):
    ok, reason = validate_payload(payload)
    if not ok:
        raise ValueError(f"payload validation failed: {reason}")
