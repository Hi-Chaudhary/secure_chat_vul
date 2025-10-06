# ChatOverlay Protocol (SOCP-style JSON)

## Transport
- WebSocket frames, text JSON
- All `payload` fields are AES-GCM encrypted after session setup.

## Handshake
1. `HELLO` (plaintext):
   {
     "type":"HELLO",
     "from":"<peer_id>",
     "pubkey_pem":"<base64-PEM>",
     "ts": <int>
   }

2. `SESSION_INIT` (plaintext fields + RSA-wrapped key):
   {
     "type":"SESSION_INIT",
     "to":"<peer_id>",
     "wrapped_key":"<b64_RSA_OAEP(AES_key)>",
     "gcm_salt":"<b64 random>",
     "ts": <int>
   }

After this, all application messages use AES-GCM with the session key for that peer pair.
Each encrypted message structure:

```
{
  "type": "ENCRYPTED",
  "from": "<peer_id>",
  "to": "<peer|*>",
  "nonce": "<b64 12B>",
  "iv": "<b64 12B>",
  "ct": "<b64 ciphertext>",
  "tag": "<b64 16B>",
  "sig": "<b64 RSA-PSS(sig over from|to|iv|nonce|ct|tag)>",
  "ts": <int>
}
```

## Application payloads (inside AES-GCM plaintext JSON)
- `LIST_REQUEST`: request peers list
- `LIST_RESPONSE`: {"peers":[{"id":"alice","fp":"..."}]}
- `MSG_PRIVATE`: {"text":"...","to":"peer_id"}
- `MSG_GROUP`: {"text":"..."}

## Identity & Fingerprint
- RSA public key fingerprint: SHA-256 over DER; hex string.

