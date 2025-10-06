# ChatOverlay Secure Overlay Chat Protocol (SOC-P v1.3)

**Group 36 — Advanced Secure Programming (University of Adelaide, 2025)**  
**Version:** SOC-P v1.3  
**Purpose:** Defines message formats, encryption, handshake, routing, and replay protection for the secure overlay chat system implemented by Group 36.

---

## 1. Overview

SOC-P v1.3 is a **peer-to-peer overlay chat protocol** for secure communication between multiple participants without a central server.  
Each node (peer) can act as both a client and a relay.  
The system supports:

- Listing all known members (`LIST_REQUEST`, `LIST_RESPONSE`)
- Private messaging (`MSG_PRIVATE`)
- Group broadcast messaging (`MSG_GROUP`)
- File transfer (`FILE_OFFER`, `FILE_CHUNK`, `FILE_END`)
- Acknowledgements and errors (`ACK`, `ERROR`)
- Heartbeat monitoring (`HEARTBEAT`, `HEARTBEAT_ACK`)

The protocol ensures **confidentiality, integrity, authenticity,** and **replay protection** through hybrid cryptography and time-bounded replay windows.

---

## 2. Transport Layer

- Transport: **WebSocket (ws://)**  
- Default hub or listener port: **9001**
- No central server: any node may accept incoming connections.
- Each node maintains sessions (peer ↔ peer) and may forward messages across connected peers (overlay routing).

---

## 3. Cryptography and Security

| Aspect | Method |
|--------|---------|
| **Public key algorithm** | RSA-3072 |
| **Session key** | 256-bit AES key (GCM mode) |
| **Key exchange** | RSA-OAEP (SHA-256) wrapped AES key |
| **Authentication** | RSA-PSS signatures over SHA-256 |
| **Integrity** | AES-GCM tag verification |
| **Replay protection** | 120 s timestamp window + nonce/IV pair cache |
| **Trust model** | TOFU (Trust-On-First-Use) — peer fingerprint pinned on first contact |
| **Encoding** | Base64 for all binary fields |

---

## 4. Connection and Handshake

1. **Outbound connection:**  
   Peer A connects to Peer B via WebSocket.

2. **HELLO exchange:**
   ```json
   {
     "type": "HELLO",
     "from": "alice",
     "uuid": "a3e2f4d0-...",
     "label": "alice",
     "pubkey_pem": "<base64 PEM>",
     "ts": 1728213456
   }
   ```
   - Each peer sends its base64-encoded PEM public key.
   - The receiver pins the fingerprint (SHA-256 of DER) into `keys/trustmap.json`.

3. **SESSION_INIT (only one side initiates):**
   - The lexicographically smaller peer generates a random AES key:
     ```json
     {
       "type": "SESSION_INIT",
       "to": "bob",
       "wrapped_key": "<base64 RSA-OAEP ciphertext>",
       "gcm_salt": "<base64 16 bytes>",
       "ts": 1728213460
     }
     ```
   - The receiver unwraps the AES key using its RSA private key and stores the session.

After this, both peers have a shared AES-GCM key and can exchange encrypted envelopes.

---

## 5. Encrypted Envelope Format

All application messages after handshake are wrapped in an **ENCRYPTED** envelope:

```json
{
  "type": "ENCRYPTED",
  "from": "alice",
  "to": "bob",
  "iv": "<base64 12 B>",
  "nonce": "<base64 12 B>",
  "ct": "<base64 ciphertext>",
  "tag": "<base64 GCM tag>",
  "sig": "<base64 RSA-PSS signature>",
  "ts": 1728213488
}
```

### Validation rules
- `ts` must be within ±120 seconds of local clock.
- `(iv|nonce)` pair must be unique per peer within window.
- Signature covers all top-level envelope fields except `sig`.

---

## 6. Application Payloads

### 6.1 `LIST_REQUEST`
```json
{ "type": "LIST_REQUEST", "ts": 1728213510 }
```

### 6.2 `LIST_RESPONSE`
```json
{
  "type": "LIST_RESPONSE",
  "peers": [ { "id": "alice", "uuid": "a3e2f4d0-...", "label": "alice", "fp": "68402674a8a80407...", "online": true } ],
  "ts": 1728213520
}
```

### 6.3 `MSG_PRIVATE`
```json
{ "type": "MSG_PRIVATE", "from": "alice", "to": "bob", "text": "hello", "ts": 1728213530 }
```
ACK example:
```json
{ "type": "ACK", "of": "MSG_PRIVATE", "from": "bob", "to": "alice", "ts": 1728213535 }
```

### 6.4 `MSG_GROUP`
```json
{ "type": "MSG_GROUP", "from": "alice", "text": "hello everyone", "mid": "m8d7fa0e", "ttl": 3, "ts": 1728213540 }
```

### 6.5 File Transfer
`FILE_OFFER`, `FILE_CHUNK`, `FILE_END` follow:

```json
{ "type": "FILE_OFFER", "id": "f1c9fa92", "name": "photo.png", "size": 84512, "sha256": "8bdf8e..." }
{ "type": "FILE_CHUNK", "id": "f1c9fa92", "seq": 0, "data_b64": "<base64 chunk>" }
{ "type": "FILE_END", "id": "f1c9fa92", "total": 12, "sha256": "8bdf8e..." }
```

### 6.6 `ACK`
```json
{ "type": "ACK", "of": "MSG_PRIVATE", "from": "bob", "to": "alice", "ts": 1728213560 }
```

### 6.7 `ERROR`
```json
{ "type": "ERROR", "code": "USER_NOT_FOUND", "detail": "Unknown user carl", "from": "hub" }
```

### 6.8 `HEARTBEAT` / `HEARTBEAT_ACK`
```json
{ "type": "HEARTBEAT", "from": "alice", "ts": 1728213580 }
{ "type": "HEARTBEAT_ACK", "from": "bob", "ts": 1728213581 }
```

---

## 7. Replay Protection

Each peer keeps a bounded cache of (nonce|iv, timestamp) per session:
- Messages older than 120 s or duplicate (nonce|iv) pairs are dropped.
- Prevents replay and duplication of valid frames.

---

## 8. File Storage and Persistence

| Data | Location | Notes |
|-------|-----------|-------|
| Peer fingerprints | `keys/trustmap.json` | TOFU store |
| Downloaded files | `downloads/<peer>/` | Auto-created |
| Seen message IDs | `data/<self_id>/state.json` | For group TTL dedup |

---

## 9. Interoperability Expectations

- Messages follow SOC-P v1.3 structures above.  
- All payload fields are case-sensitive and UTF-8 encoded.  
- Other groups’ clients can interoperate if they:
  - Support RSA-OAEP + AES-GCM hybrid encryption
  - Use the same message types and routing rules
  - Pin fingerprints via TOFU and include sender identifiers

---

## 10. Security Notes

- **Confidentiality:** AES-GCM per link.  
- **Integrity & Authenticity:** RSA-PSS signatures on each envelope.  
- **Forward Secrecy:** Not full PFS (static RSA keys), but session keys can be rotated.  
- **Backdoors:** Two intentional vulnerabilities exist in the Week 9 build for peer review (undisclosed until Week 11).

---

**End of Specification**  
*(SOC-P v1.3, Group 36 — Advanced Secure Programming, University of Adelaide, 2025)*
