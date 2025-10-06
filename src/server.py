# src/server.py
"""
Secure WebSocket server (public + private messages).
- Handshake: client receives server public key; client returns AES key encrypted with server RSA pubkey.
- After handshake, all app messages are AES-GCM encrypted inside the envelope.payload.

This version includes:
• Guaranteed DEBUG logging to console (so you can see the per-client loop and incoming frames)
• A solid per-client receive loop that logs RAW frames and decrypts/dispatches
• Clean disconnect handling and system broadcast on join/leave
• Removal of deprecated WebSocketServerProtocol import (not needed)
"""
from __future__ import annotations

import asyncio
import json
import argparse
import logging
from typing import Dict, Any, Optional

import websockets

from src.crypto import (
    load_rsa_private_key,
    load_rsa_public_key,
    rsa_decrypt_with_private,
    generate_rsa_keypair,
    aesgcm_decrypt,
    aesgcm_encrypt,
    b64enc,
    b64dec,
)
from src.protocol import make_envelope, parse_envelope
from src.utils import LOG, read_file_bytes, write_file_bytes, ensure_dir
import os

# ---------- configuration for RSA keys ----------
KEY_DIR = "examples/demo_keys"
RSA_PRIV_FILE = os.path.join(KEY_DIR, "server_priv.pem")
RSA_PUB_FILE = os.path.join(KEY_DIR, "server_pub.pem")


class ClientState:
    def __init__(self, username: str, ws: websockets.WebSocketServerProtocol):
        self.username = username
        self.ws = ws
        self.aes_key: Optional[bytes] = None  # set after handshake


class ChatServer:
    def __init__(self):
        self.clients: Dict[str, ClientState] = {}  # username -> state
        self.lock = asyncio.Lock()
        self.priv_key = None  # set in load_or_generate_keys()
        self.pub_pem: bytes | None = None

    # ----- key management -----
    async def load_or_generate_keys(self):
        ensure_dir(KEY_DIR)
        if not (os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE)):
            LOG.info("Demo keys not found, generating RSA keypair...")
            priv_pem, pub_pem = generate_rsa_keypair()
            write_file_bytes(RSA_PRIV_FILE, priv_pem)
            write_file_bytes(RSA_PUB_FILE, pub_pem)
        else:
            priv_pem = read_file_bytes(RSA_PRIV_FILE)
            pub_pem = read_file_bytes(RSA_PUB_FILE)
        self.priv_key = load_rsa_private_key(priv_pem)
        self.pub_pem = pub_pem

    # ----- per-connection handler -----
    async def handler(self, ws: websockets.WebSocketServerProtocol):
        # 1) Send server public key so client can start handshake
        await ws.send(json.dumps({
            "type": "HANDSHAKE_INIT",
            "server_pub": self.pub_pem.decode("utf-8"),
        }))

        # 2) Receive handshake from client
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=15.0)
            LOG.info("RAW HANDSHAKE MSG: %s", raw)
        except Exception:
            LOG.warning("Handshake timeout or error")
            await ws.close()
            return

        # 3) Validate + decrypt AES key
        try:
            env = parse_envelope(raw)
            if env["type"] != "HANDSHAKE":
                raise ValueError("Expected HANDSHAKE")
            username = env.get("from")
            if not username:
                raise ValueError("Missing username in handshake")
            payload = env.get("payload") or {}
            enc_key_b64 = payload.get("enc_key")
            if not enc_key_b64:
                raise ValueError("Missing enc_key in handshake payload")
            aes_key = rsa_decrypt_with_private(self.priv_key, b64dec(enc_key_b64))
            LOG.debug("Handshake decrypt OK for user=%s", username)
        except Exception as e:
            LOG.exception("Handshake failed for incoming client: %s", e)
            await ws.close()
            return

        # 4) Register client and broadcast join
        state = ClientState(username=username, ws=ws)
        state.aes_key = aes_key
        async with self.lock:
            if username in self.clients:
                LOG.error("Username collision for %s", username)
                await ws.send(json.dumps({"type": "ACK", "meta": {"status": "ERROR", "reason": "username taken"}}))
                await ws.close()
                return
            self.clients[username] = state
            LOG.info("Client joined: %s", username)
            try:
                await self.broadcast_system(f"{username} has joined the public channel", exclude=username)
            except Exception:
                LOG.exception("broadcast_system(join) failed for %s (continuing)", username)

        # 5) Enter per-client receive loop
        try:
            await self.client_loop(state)
        except websockets.ConnectionClosed as e:
            LOG.info("Connection closed for %s: %s", state.username, e)
        except Exception:
            LOG.exception("Unhandled error in client_loop for %s", state.username)
        finally:
            # 6) Cleanup on disconnect
            async with self.lock:
                if state.username in self.clients:
                    self.clients.pop(state.username, None)
            try:
                await self.broadcast_system(f"{state.username} has left the public channel", exclude=state.username)
            except Exception:
                LOG.exception("broadcast_system(leave) failed for %s (continuing)", state.username)
            LOG.info("Client left: %s", state.username)

    # ----- recv loop -----
    async def client_loop(self, state: ClientState):
        LOG.debug("ENTER client_loop for %s", state.username)
        ws = state.ws
        while True:
            raw = await ws.recv()  # awaits next frame from that client
            LOG.debug("RAW FROM %s: %s", state.username, raw)

            # 1) Parse the envelope (outer JSON)
            try:
                env = parse_envelope(raw)
            except Exception:
                LOG.warning("Invalid envelope from %s", state.username)
                continue

            # 2) Decrypt the inner JSON using this client's AES key
            payload = env.get("payload") or {}
            if not state.aes_key:
                LOG.warning("No AES key for client %s", state.username)
                continue
            try:
                nonce = b64dec(payload["nonce"])  # raises if missing
                ciphertext = b64dec(payload["ciphertext"])  # raises if missing
                inner_bytes = aesgcm_decrypt(state.aes_key, nonce, ciphertext, associated_data=None)
                inner = json.loads(inner_bytes.decode("utf-8"))
            except Exception:
                LOG.exception("Decrypt/parse failed for message from %s", state.username)
                continue

            # 3) Dispatch based on inner type
            mtype = inner.get("type")
            if mtype == "PUBLIC_MSG":
                text = inner.get("text", "")
                LOG.info("PUBLIC from %s: %s", state.username, text)
                await self.broadcast_message(state.username, inner)
            elif mtype == "PRIVATE_MSG":
                to = inner.get("to")
                await self.forward_private(state.username, to, inner)
            else:
                LOG.debug("Unhandled inner message type from %s: %s", state.username, mtype)

    # ----- broadcast helpers -----
    async def _send_encrypted(self, st: ClientState, inner: Dict[str, Any], outer_type: str, sender: str):
        """Encrypt inner payload for a specific client and send."""
        nonce, ct = aesgcm_encrypt(st.aes_key, json.dumps(inner).encode("utf-8"), associated_data=None)
        env = {
            "type": outer_type,
            "from": sender,
            "to": inner.get("to", "*"),
            "payload": {
                "nonce": b64enc(nonce),
                "ciphertext": b64enc(ct),
            },
            "meta": {},
        }
        await st.ws.send(json.dumps(env))

    async def broadcast_message(self, sender: str, inner_payload: Dict[str, Any]):
        async with self.lock:
            inner = {"type": "PUBLIC_MSG", "text": inner_payload.get("text", "")}
            for uname, st in list(self.clients.items()):
                try:
                    await self._send_encrypted(st, inner, outer_type="PUBLIC_MSG", sender=sender)
                except Exception:
                    LOG.exception("Broadcast to %s failed", uname)

    async def forward_private(self, sender: str, recipient: str | None, inner_payload: Dict[str, Any]):
        if not recipient:
            LOG.warning("PRIVATE_MSG from %s missing 'to' field", sender)
            return
        async with self.lock:
            st = self.clients.get(recipient)
            if not st:
                LOG.info("PRIVATE_MSG to missing user %s", recipient)
                return
            try:
                inner = {"type": "PRIVATE_MSG", "to": recipient, "text": inner_payload.get("text", "")}
                await self._send_encrypted(st, inner, outer_type="PRIVATE_MSG", sender=sender)
            except Exception:
                LOG.exception("Private forward to %s failed", recipient)

    async def broadcast_system(self, message: str, exclude: Optional[str] = None):
        inner = {"type": "PUBLIC_MSG", "text": f"[system] {message}"}
        async with self.lock:
            for uname, st in list(self.clients.items()):
                if exclude and uname == exclude:
                    continue
                try:
                    await self._send_encrypted(st, inner, outer_type="SYSTEM", sender="server")
                except Exception:
                    LOG.exception("System broadcast to %s failed", uname)


async def main(port: int):
    server = ChatServer()
    await server.load_or_generate_keys()
    LOG.info("Starting server on port %d", port)
    async with websockets.serve(server.handler, "0.0.0.0", port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000, help="WebSocket server port")
    args = parser.parse_args()

    # Make sure DEBUG prints actually appear on your console
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.getLogger("websockets").setLevel(logging.WARNING)

    asyncio.run(main(args.port))
