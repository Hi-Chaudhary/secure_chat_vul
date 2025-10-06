# src/client.py
"""
Secure WebSocket client (simple CLI).
Performs handshake and then allows simple send/receive on the public channel.
"""
from __future__ import annotations
import asyncio
import json
import argparse
import logging
import websockets
from typing import Any, Dict
from src.crypto import (
    load_rsa_public_key, rsa_encrypt_with_public, generate_aes_key,
    aesgcm_encrypt, aesgcm_decrypt, b64enc, b64dec
)
from src.protocol import make_envelope, parse_envelope
from src.utils import LOG
import sys

async def listen_loop(ws, aes_key: bytes):
    async for raw in ws:
        try:
            env = parse_envelope(raw)
        except Exception:
            LOG.warning("Received invalid envelope")
            continue
        payload = env.get("payload", {})
        try:
            nonce = b64dec(payload["nonce"])
            ciphertext = b64dec(payload["ciphertext"])
            pt = aesgcm_decrypt(aes_key, nonce, ciphertext, associated_data=None)
            inner = json.loads(pt.decode("utf-8"))
            # print to console
            mtype = inner.get("type")
            if mtype == "PUBLIC_MSG":
                print(f"[PUBLIC] {env.get('from')}: {inner.get('text')}")
            elif mtype == "PRIVATE_MSG":
                print(f"[PRIVATE] {env.get('from')} -> {inner.get('to')}: {inner.get('text')}")
            else:
                print(f"[MSG] {inner}")
        except Exception:
            LOG.exception("Failed to decrypt incoming message")


async def interactive_send(ws, username: str, aes_key: bytes):
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            await ws.close()
            break
        line = line.strip()
        if not line:
            continue
        if line.startswith("/pm "):
            parts = line.split(" ", 2)
            if len(parts) < 3:
                print("Usage: /pm <user> <message>")
                continue
            to, text = parts[1], parts[2]
            inner = {"type": "PRIVATE_MSG", "to": to, "text": text}
        elif line.startswith("/quit"):
            await ws.close()
            return
        else:
            inner = {"type": "PUBLIC_MSG", "text": line}

        plaintext = json.dumps(inner).encode("utf-8")
        nonce, ct = aesgcm_encrypt(aes_key, plaintext, associated_data=None)
        payload = {"nonce": b64enc(nonce), "ciphertext": b64enc(ct)}
        envelope = make_envelope(inner["type"], username, inner.get("to", "*"), payload)
        await ws.send(envelope)
        # NEW: local echo so you know the send happened
        if inner["type"] == "PUBLIC_MSG":
            print(f">> sent PUBLIC: {inner.get('text','')}")
        else:
            print(f">> sent PRIVATE to {inner.get('to')}: {inner.get('text','')}")


async def run(uri: str, username: str):
    async with websockets.connect(uri) as ws:
        # wait for HANDSHAKE_INIT from server
        raw = await ws.recv()
        data = json.loads(raw)
        server_pub_pem = data.get("server_pub")
        if not server_pub_pem:
            LOG.error("Server did not send public key")
            return
        server_pub = load_rsa_public_key(server_pub_pem.encode("utf-8"))

        # generate ephemeral AES key and send encrypted copy inside HANDSHAKE envelope
        aes_key = generate_aes_key()
        enc_key = rsa_encrypt_with_public(server_pub, aes_key)
        payload = {"enc_key": b64enc(enc_key)}
        env = make_envelope("HANDSHAKE", username, "server", payload)
        await ws.send(env)

        # start receiver and interactive sender
        await asyncio.gather(listen_loop(ws, aes_key), interactive_send(ws, username, aes_key))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--connect", type=str, default="ws://localhost:9000", help="WebSocket URI")
    parser.add_argument("--username", type=str, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.connect, args.username))
