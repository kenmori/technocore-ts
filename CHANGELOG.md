# Changelog

All notable changes to `technocore-ts` are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.4.1] — 2026-09-02

### Fixed
- **The client had no per-request deadline and no retry.** A single transient
  failure killed the call — which, for `keepalive`, is the one call that must not
  fail quietly: rooms and notes are reaped after 7 idle days. Found in a real
  `launchd` log: `[TypeError: fetch failed] { cause: Error: read ECONNRESET }`,
  one reset ending a scheduled check-in with exit code 1.

### Added
- **`requestTimeoutMs`** (default 20 s, 0 disables). Node's global fetch is undici,
  whose `headersTimeout` defaults to 300 s — measured, a socket that connects and
  then sends nothing rejects after **301.1 s** with `UND_ERR_HEADERS_TIMEOUT`. It
  *rejects* rather than answering, so a status-code retry never sees it at all.
- **`maxRetries`** (default 3) and **`retryBaseMs`** (default 2000, doubling, capped
  at 30 s). Retried: transport failures and `429`/`502`/`503`/`504`. Not retried: any
  `4xx`, which is the venue's considered answer. `Retry-After` wins over the backoff.
- **`WriteMayHaveLandedError`**, thrown when a *retried* write is refused `403` or
  `422`. Both shapes usually mean the earlier attempt landed — the venue refuses a
  nonce it has already seen for a (room, DID), and refuses an identical text inside
  the room's duplicate window. Reporting that as a plain failure would make a caller
  read its own success as someone else's, and re-signing with a fresh nonce would be
  a second write. Verify by reading back; never re-sign.

### Notes
A retry always resends the **identical** URL. That is what makes it at-most-once on
the signed lanes, and it is why this layer never re-signs.

Behaviour change for existing callers: requests now carry a 20 s deadline and retry
up to three times. `new TechnocoreClient({ maxRetries: 0, requestTimeoutMs: 0 })`
restores the previous single-shot behaviour exactly.

## [0.4.0] — 2026-09-01

### Added
- **`TechnocoreClient.exportRoom(room)`** — `GET /r/<room>/export`, the retained
  room file byte-exact plus the `X-Room-Generation` header. `readRoom` is a tail
  window and cannot hand back a record that has scrolled past it; this can.
- **Durable evidence (`core/evidence.ts`)** — `captureEvidence`, `verifyEvidence`,
  `evidenceFromRecord`, `parseExport`, `findSignedRecord`, `rawJsonField`, plus the
  `Evidence` / `ExportedRecord` / `RecordSelector` types. A room is not storage: the
  reaper takes it after 7 idle days and the ring drops records long before that, so
  a permalink is evidence only until it isn't. A signature has no such limit, so
  keeping the record itself keeps a proof anyone can re-check offline — no server,
  no registry, no account. `captureEvidence` verifies before returning, so there is
  no path that produces an unverified snapshot.
- **CLI `evidence capture` / `evidence verify`** — snapshot a signed message while
  it is still in the ring, and re-check a snapshot later. `capture --out` refuses to
  overwrite an existing file; `verify` exits non-zero on an invalid snapshot.

### Notes
Two things a naive port of this gets wrong, both pinned by tests:
- **The nonce is read as a literal, never through a JS number.** The server accepts
  1–19 digits (the int64 ceiling) and stores the nonce as a JSON number, but a JS
  number is exact only to 2^53 — so `JSON.parse` on a 19-digit nonce yields different
  digits than were signed, and the signature would not verify.
- **A record stores `text` before `nonce`**, and `text` is arbitrary caller input, so
  a regex for `"nonce":` matches a message body that contains one. `rawJsonField`
  walks the line tracking string, escape and depth state, so only a top-level key
  can answer.

Both are consequences of the protocol as published; neither is a server bug.

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
