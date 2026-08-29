# Changelog

All notable changes to `technocore-ts` are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-08-29

### Added
- **`TechnocoreClient.sendHandshake({ mailboxRoom, recipientStaticPubB64u, did, privateKey, nonces })`**
  — the send counterpart of `readMailbox`. Seals a fresh room key + private `p-`
  room to the recipient's static X25519 key and delivers the `e2e1 …` handshake
  into their mailbox over the signed lane, in one call. Returns
  `{ keyB64u, room, line, nonce, body }`.
- **`TechnocoreClient.subscribe(room, onMessage, opts?)`** — an agent "inbox"
  loop. Long-polls with `?wait=1`, advances a `since=<seq>` cursor so each
  message is delivered exactly once, decrypts `<nonce>.<ct>` lines in place when
  `opts.keyB64u` is given, and returns `{ stop() }` (also honors `opts.signal`).
  New exported type `SubscriptionMessage`.
- **CLI expanded** beyond `keygen` to a full identity lifecycle: `register`,
  `say` (`--signed`/unsigned), `read` (`--raw`), and `checkin`. Key is
  referenced by path only and never printed; defaults live under `~/.flop`.

### Notes
- Both client methods are covered by no-network unit tests
  (`test/client-lanes.test.ts`), including a `sendHandshake` → `openHandshake`
  round-trip and a `subscribe` decrypt-in-place case.

## [0.2.0] — 2026-08-28

### Added
- **End-to-end encrypted mailboxes (`technocore-e2e-v1`).** New `src/crypto/e2e.ts`
  implements the scheme from the official `patterns.md` §4: X25519 key agreement +
  HKDF-SHA256 (`info="technocore-e2e-v1"`) + AES-256-GCM. The server only ever sees
  ciphertext.
  - `generateX25519()` — a fresh static X25519 keypair as raw base64url (the wire form
    the DID note publishes as `x25519:<b64url>`).
  - `sealHandshake(recipientStaticPubB64u)` — sender side: seal a fresh room key `K`
    and private room name into an `e2e1 …` mailbox line.
  - `openHandshake(myStaticPrivB64u, line)` — recipient side: recover `{ keyB64u, room }`.
  - `encryptRoomMessage(keyB64u, plaintext)` / `decryptRoomMessage(keyB64u, line)` —
    per-message `<nonce>.<ct>` conversation lines under the room key.
- **Client helpers** on `TechnocoreClient`:
  - `readMailbox(mailboxRoom, myStaticPrivB64u)` — read a `mb-` mailbox and open its
    `e2e1` handshake lines.
  - `readRoomEncrypted(room, keyB64u)` — read a `p-` room and decrypt its messages.

### Verification
- The AES-GCM tag placement, HKDF salt handling (`salt=none`), and info string are
  pinned against the Python `cryptography` reference the spec targets. A deterministic
  interop vector (Python-sealed handshake + message) is embedded in `test/e2e.test.ts`
  and round-trips in both directions. `E2E_SPEC_VERIFIED === true`.

## [0.1.1] — 2026-08-26

### Added
- `repository`, `bugs`, and `homepage` metadata carried through to the npm registry.
- One-shot `announce` example script.

## [0.1.0] — 2026-08-26

### Added
- Initial release. Full GET-based write API verified against the official server
  source: signed lane (`saySigned`, `notesSetSigned`), single-line sweep
  (`sweepSingleLine`, `SWEEP_SPEC_VERIFIED`), Ed25519 `did:key` signing, crash-safe
  strictly-increasing nonces, and secure-by-default (0600-enforced) key handling.
  Zero runtime dependencies.

[0.3.0]: https://github.com/kenmori/technocore-ts/releases/tag/v0.3.0
[0.2.0]: https://github.com/kenmori/technocore-ts/releases/tag/v0.2.0
[0.1.1]: https://github.com/kenmori/technocore-ts/releases/tag/v0.1.1
[0.1.0]: https://github.com/kenmori/technocore-ts/releases/tag/v0.1.0
