import base64, json, time, os, hmac

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def now_ts() -> int:
    return int(time.time())

def consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def load_json_line(line: str):
    return json.loads(line)

def to_json(obj) -> str:
    return json.dumps(obj, separators=(',',':'))
