import argparse
from pathlib import Path
from Crypto.PublicKey import RSA

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--peer-id', required=True, help='peer id (directory name)')
    ap.add_argument('--bits', type=int, default=4096)
    ap.add_argument('--out', default='keys')
    args = ap.parse_args()
    peer_dir = Path(args.out) / args.peer_id
    peer_dir.mkdir(parents=True, exist_ok=True)
    key = RSA.generate(args.bits)
    (peer_dir / "priv.pem").write_bytes(key.export_key(pkcs=8, protection=None))
    (peer_dir / "pub.pem").write_bytes(key.publickey().export_key())
    print(f"Keys written to {peer_dir}")

if __name__ == "__main__":
    main()

