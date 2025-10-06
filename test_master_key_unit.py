# test_master_key_unit.py
import os, base64, importlib

# import your crypto module (adjust path if different)
crypto = importlib.import_module("src.crypto")  # or "crypto" if not in package

def hex_of(b): return b.hex()

def test_without_flags():
    os.environ.pop("SOCP_ALWAYS_USE_MASTER", None)
    os.environ.pop("SOCP_USE_ENV_MASTER", None)
    os.environ.pop("SOCP_MASTER_KEY_B64", None)
    k1 = crypto.gen_aes_key()
    k2 = crypto.gen_aes_key()
    print("WITHOUT flags: len(k1)=", len(k1), "k1==k2?", k1==k2)

def test_with_env_master():
    # create a 32-byte master key and set it base64
    mk = b"X"*32
    b64 = base64.b64encode(mk).decode()
    os.environ["SOCP_MASTER_KEY_B64"] = b64
    os.environ["SOCP_ALWAYS_USE_MASTER"] = "1"   # force usage
    k3 = crypto.gen_aes_key()
    k4 = crypto.gen_aes_key()
    print("WITH env master+always: len(k3)=", len(k3), "k3==mk?", k3==mk, "k3==k4?", k3==k4)

if __name__ == "__main__":
    test_without_flags()
    test_with_env_master()
