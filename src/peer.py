# src/peer.py
import asyncio, json, websockets
import uuid as _uuid
from typing import List, Dict, Any, Optional
from .utils import to_json
from .keymgr import load_priv, load_pub, pub_pem_b64, load_or_create_uuid
from .storage import State
from .handlers import Handlers
from .protocol import MAX_WS_FRAME

async def _safe_send(ws, data: str):
    try:
        await ws.send(data)
    except Exception:
        pass

class Peer:
    HEARTBEAT_INTERVAL = 10  # seconds between heartbeats
    def __init__(self, name: str, port: int, keys_dir: str, peers: List[str]):
        self.name = name
        self.port = port
        self.keys_dir = keys_dir
        self.peers_urls = peers
        self.node_uuid = load_or_create_uuid(self.keys_dir)

        self.priv = load_priv(keys_dir)
        self.pub  = load_pub(keys_dir)
        self.pub_b64 = pub_pem_b64(self.pub)

        # Persist JSON under data/<name>/
        self.state = State(self_id=name, data_root="data")
        self.state.self_uuid = self.node_uuid               
        self.state.self_label = self.name  

        # connection maps
        self.out_conns: Dict[str, websockets.WebSocketClientProtocol] = {}
        self.in_conns:  Dict[str, websockets.WebSocketServerProtocol] = {}

        # temp_label -> real_name ; real_name -> label
        self.alias: Dict[str, str] = {}
        self.reverse_alias: Dict[str, str] = {}

        self.handlers = Handlers(
            state=self.state,
            privkey=self.priv,
            self_pub_b64=self.pub_b64,
            send_json_func=self._send_json,
            register_alias_func=self._register_alias
        )

        self.server = None
        self._hb_task = None

    async def start(self):
        # Enforce per-frame size at protocol layer too
        self.server = await websockets.serve(self._server_handler, "0.0.0.0", self.port, max_size=MAX_WS_FRAME)
        print(f"[{self.name}] listening ws://0.0.0.0:{self.port}")
        # Start periodic encrypted heartbeats to keep presence fresh
        self._hb_task = asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._connect_to_peers())

    async def _heartbeat_loop(self):
        """
        Periodically send encrypted HEARTBEAT payloads to all peers with whom
        we already have a session. This keeps `last_seen` fresh on the other side,
        so `/list` shows them online even when chats are idle.
        """
        try:
            while True:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL if hasattr(self, "HEARTBEAT_INTERVAL") else 10)
                # Snapshot the current sessions to avoid mutation while iterating
                try:
                    peers = list(self.state.sessions.keys())
                except Exception:
                    peers = []
                if not peers:
                    continue
                for peer_name in peers:
                    try:
                        await self.handlers.send_application(peer_name, {
                            "type": "HEARTBEAT",
                            "from": self.state.self_id,
                            "ts": __import__("time").time().__int__(),
                        })
                    except Exception:
                        # Ignore per-peer send errors; next tick will retry
                        pass
        except asyncio.CancelledError:
            # Graceful shutdown of the loop
            return

    async def _server_handler(self, ws: websockets.WebSocketServerProtocol):
        temp_id = f"in-{id(ws)}"
        self.in_conns[temp_id] = ws
        try:
            await self.handlers.on_open_connection(temp_id)
            async for msg in ws:
                await self.handlers.on_message(msg, temp_id)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.in_conns.pop(temp_id, None)
            real = self.alias.pop(temp_id, None)
            if real:
                self.reverse_alias.pop(real, None)
        # tell the handler to drop any sessions bound to this link/peer
        try:
            self.handlers.on_connection_closed(temp_id)
        except Exception:
            pass

    async def _connect_to_peers(self):
        await asyncio.sleep(0.2)
        for url in self.peers_urls:
            asyncio.create_task(self._dial_peer(url))

    async def _dial_peer(self, url: str):
        temp_id = url.split("//")[-1]  # e.g., localhost:9002
        while True:
            try:
                ws = await websockets.connect(url, max_size=MAX_WS_FRAME)
                self.out_conns[temp_id] = ws
                print(f"[{self.name}] connected -> {temp_id}")
                await self.handlers.on_open_connection(temp_id)
                async for msg in ws:
                    await self.handlers.on_message(msg, temp_id)
            except Exception as e:
                print(f"[{self.name}] connect error {url}: {e}; retrying in 2s")
                await asyncio.sleep(2)
            finally:
                self.out_conns.pop(temp_id, None)
                real = self.alias.pop(temp_id, None)
                if real:
                    self.reverse_alias.pop(real, None)
            # tell the handler to drop any sessions bound to this link/peer
            try:
                self.handlers.on_connection_closed(temp_id)
            except Exception:
                pass

    def _register_alias(self, temp_label: str, real_name: str):
        self.alias[temp_label] = real_name
        if temp_label in self.out_conns or temp_label in self.in_conns:
            self.reverse_alias[real_name] = temp_label

    def _resolve_recipient_id(self, to_id: Optional[str]) -> Optional[str]:
        """
        Accept either a display name (current behavior) or a UUIDv4.
        If a UUID matches a known peer's UUID, return that peer's display id (name).
        Otherwise, return the original value unchanged.
        """
        if not to_id:
            return to_id
        # Try to parse as UUID; if it fails, it's just a normal name
        try:
            norm = str(_uuid.UUID(str(to_id)))
        except Exception:
            return to_id
        # Map uuid -> existing display name from the state.peers table
        for name, p in self.state.peers.items():
            if getattr(p, "uuid", None) == norm:
                return name
        return to_id

    async def _send_json(self, to_id: Optional[str], obj: Dict[str, Any]):
        # 1) Resolve UUIDs to display names for routing
        resolved_to = self._resolve_recipient_id(to_id)

        # 2) ALSO fix the envelope so receivers see their expected name (not UUID)
        if isinstance(obj, dict) and "to" in obj and obj["to"] not in (None, "*"):
            # shallow copy to avoid mutating caller’s dict unexpectedly
            obj = dict(obj)
            obj["to"] = self._resolve_recipient_id(obj["to"])

        data = to_json(obj)
        # ... then continue your existing logic, but use `resolved_to` everywhere
        if resolved_to is None or resolved_to == "*":
            for ws in list(self.out_conns.values()):
                await _safe_send(ws, data)
            for ws in list(self.in_conns.values()):
                await _safe_send(ws, data)
            return

        label = self.reverse_alias.get(resolved_to)
        if label:
            ws = self.out_conns.get(label) or self.in_conns.get(label)
            if ws:
                await _safe_send(ws, data)
                return

        # fallback broadcast; only intended peer will accept/decrypt
        for ws in list(self.out_conns.values()):
            await _safe_send(ws, data)
        for ws in list(self.in_conns.values()):
            await _safe_send(ws, data)
