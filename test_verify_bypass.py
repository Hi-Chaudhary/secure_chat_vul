import os
import importlib

# adjust if your package is different; project uses "src" package
# this will import the patched function from your codebase
mod = importlib.import_module("src.protocol")
verify_envelope = getattr(mod, "verify_envelope")

# Minimal fake envelope: only 'sig' presence matters for the bypass
fake_env = {"type": "FAKE", "from": "attacker", "to": "victim", "sig": "ZmFrZVNpZ24="}

print("=== Test 1: without SOCP_DEBUG_TRUST_ALL (should be False) ===")
# Ensure flag is unset or "0"
os.environ.pop("SOCP_DEBUG_TRUST_ALL", None)
print("env SOCP_DEBUG_TRUST_ALL =", os.environ.get("SOCP_DEBUG_TRUST_ALL"))
try:
    ok = verify_envelope(fake_env, None)   # pubkey not used when bypass active
except Exception as e:
    print("verify_envelope raised:", e)
else:
    print("verify_envelope returned:", ok)

print("\n=== Test 2: with SOCP_DEBUG_TRUST_ALL=1 (should be True) ===")
os.environ["SOCP_DEBUG_TRUST_ALL"] = "1"
print("env SOCP_DEBUG_TRUST_ALL =", os.environ.get("SOCP_DEBUG_TRUST_ALL"))
try:
    ok2 = verify_envelope(fake_env, None)
except Exception as e:
    print("verify_envelope raised:", e)
else:
    print("verify_envelope returned:", ok2)
