import argparse, asyncio, json, os, sys
from typing import List
from .peer import Peer
from .utils import now_ts

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', type=str, help='JSON config file')
    ap.add_argument('--name', type=str, help='peer id/name')
    ap.add_argument('--port', type=int, help='listen port')
    ap.add_argument('--keys', type=str, help='keys dir (with priv.pem/pub.pem)')
    ap.add_argument('--peers', type=str, help='comma-separated ws://host:port entries', default="")
    return ap.parse_args()

def load_config(path: str):
    with open(path,"r") as f:
        return json.load(f)

async def run_interactive(peer: Peer):
    await peer.start()
    # REPL (SOCP command names)
    print("Commands: /list | /tell --to <id> --text <msg> | /all --text <msg> | /file --to <id> --path <file> | /quit")
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            await asyncio.sleep(0.1)
            continue
        line = line.strip()
        if line == "/quit":
            print("bye"); os._exit(0)

        # -----------------------
        # /list  -> LIST_REQUEST
        # -----------------------
        if line.startswith("/list"):
            payload = {"type": "LIST_REQUEST", "ts": now_ts()} 
            await peer.handlers.send_application("*", payload)
            continue

        # -----------------------
        # /tell  -> MSG_PRIVATE (SOCP: 'tell' is the CLI alias)
        # usage: /tell --to bob --text hello there
        # -----------------------
        if line.startswith("/tell"):
            to = None
            text = ""
            parts = line.split()
            if "--to" in parts:
                try:
                    to = parts[parts.index("--to") + 1]
                except Exception:
                    to = None
            if "--text" in parts:
                try:
                    idx = parts.index("--text") + 1
                    text = " ".join(parts[idx:])
                except Exception:
                    text = ""
            payload = {"type": "MSG_PRIVATE", "to": to, "text": text}
            await peer.handlers.send_application(to, payload)
            continue

        # -----------------------
        # /all -> MSG_GROUP (broadcast to public channel)
        # usage: /all --text hi everyone
        # -----------------------
        if line.startswith("/all"):
            text = ""
            parts = line.split()
            if "--text" in parts:
                try:
                    idx = parts.index("--text") + 1
                    text = " ".join(parts[idx:])
                except Exception:
                    text = ""
            payload = {"type": "MSG_GROUP", "text": text}
            await peer.handlers.send_application("*", payload)
            continue

        # -----------------------
        # /file -> file transfer (maps to existing send_file)
        # usage: /file --to bob --path <path>
        # -----------------------
        if line.startswith("/file"):
            parts = line.split()
            to = None
            path = None
            if "--to" in parts:
                try:
                    to = parts[parts.index("--to") + 1]
                except Exception:
                    to = None
            if "--path" in parts:
                try:
                    path = " ".join(parts[parts.index("--path") + 1:])
                except Exception:
                    path = None
            if not (to and path):
                print("usage: /file --to <peer> --path <file>")
            else:
                await peer.handlers.send_file(to, path)
            continue

        # Unknown command: try helpful hint
        print("Unknown command. Supported: /list | /tell | /all | /file | /quit")


def main():
    args = parse_args()
    cfg = {}
    if args.config:
        cfg = load_config(args.config)
    name = args.name or cfg.get("name")
    port = args.port or int(cfg.get("port", 0))
    keys = args.keys or cfg.get("keys_dir")
    peers = args.peers or ",".join(cfg.get("peers", []))
    peers_list = [p.strip() for p in peers.split(",") if p.strip()]
    if not (name and port and keys is not None):
        print("Missing required args: --name --port --keys (or --config)"); sys.exit(1)
    p = Peer(name=name, port=port, keys_dir=keys, peers=peers_list)
    asyncio.run(run_interactive(p))

if __name__ == "__main__":
    main()
