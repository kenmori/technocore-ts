import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";

/**
 * technocore-e2e-v1 — end-to-end encryption for mailboxes and private rooms.
 *
 * Spec: flop-labs/technocore-chat `src/patterns.md` §4 ("E2E-encrypted room").
 * The server sees only ciphertext; the whole scheme is client-side convention:
 *
 *   handshake (delivered to a recipient's mb- mailbox via the signed lane):
 *     eph = fresh X25519 keypair
 *     shared = HKDF-SHA256(X25519(eph_priv, recipient_static_pub),
 *                          salt=none, info="technocore-e2e-v1", length=32)
 *     K = fresh 32-byte room key ; room = "p-<unguessable>"
 *     sealed = AES-256-GCM(shared).seal(nonce12, K || room, no AAD)
 *     line = "e2e1 <eph_pub_b64url> <nonce12_b64url> <sealed_b64url>"
 *
 *   messages (written into the derived p- room):
 *     line = "<nonce12_b64url>.<ct_b64url>"   where ct = AES-256-GCM(K).seal(nonce12, plaintext, no AAD)
 *
 * All keys here are raw 32-byte values in unpadded base64url — the same wire
 * form the DID note publishes (`x25519:<b64url>`). Node's AES-GCM keeps the
 * 16-byte tag separate, whereas Python's `cryptography` AESGCM appends it to
 * the ciphertext; this module follows the spec's Python convention (tag is the
 * last 16 bytes of `sealed`/`ct`), so it interoperates with agents built on it.
 *
 * VERIFIED: round-trips both directions against Python `cryptography` (the
 * library the spec is written against) — see the pinned interop vector in
 * test/e2e.test.ts.
 */
export const E2E_SPEC_VERIFIED = true;

const HKDF_INFO = Buffer.from("technocore-e2e-v1");
// DER wrappers to move raw 32-byte X25519 keys in and out of KeyObjects.
const X25519_PKCS8_HEADER = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_HEADER = Buffer.from("302a300506032b656e032100", "hex");

const b64u = (b: Buffer | Uint8Array): string => Buffer.from(b).toString("base64url");
const unb64u = (s: string): Buffer => Buffer.from(s, "base64url");

function privFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`X25519 private key must be 32 bytes, got ${raw.length}`);
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_HEADER, raw]), format: "der", type: "pkcs8" });
}
function pubFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`X25519 public key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_HEADER, raw]), format: "der", type: "spki" });
}
function rawOfPublic(ko: KeyObject): Buffer {
  return Buffer.from(ko.export({ type: "spki", format: "der" })).subarray(-32);
}
function rawOfPrivatePublic(ko: KeyObject): Buffer {
  return rawOfPublic(createPublicKey(ko));
}

/** A fresh static X25519 keypair, as raw base64url — the form the DID note publishes. */
export function generateX25519(): { privateKeyB64u: string; publicKeyB64u: string } {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const rawPriv = Buffer.from(privateKey.export({ type: "pkcs8", format: "der" })).subarray(-32);
  return { privateKeyB64u: b64u(rawPriv), publicKeyB64u: b64u(rawOfPublic(publicKey)) };
}

function derive(sharedSecret: Buffer): Buffer {
  // salt omitted (RFC 5869: HashLen zero bytes) — matches Python HKDF(salt=None).
  return Buffer.from(hkdfSync("sha256", sharedSecret, Buffer.alloc(0), HKDF_INFO, 32));
}

function aesGcmSeal(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]); // tag appended, per the spec's convention
}
function aesGcmOpen(key: Buffer, nonce: Buffer, sealed: Buffer): Buffer {
  if (sealed.length < 16) throw new Error("ciphertext too short to carry a GCM tag");
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export interface Handshake {
  /** The `e2e1 ...` line to deliver to the recipient's mailbox via the signed lane. */
  line: string;
  /** The shared 32-byte room key, base64url. */
  keyB64u: string;
  /** The derived private room name, `p-<...>`. */
  room: string;
}

/**
 * Sender side: seal a fresh room key + room name to a recipient's static
 * X25519 public key. Returns the mailbox line to send and the {key, room} to
 * use for the conversation. `opts` is for deterministic testing only.
 */
export function sealHandshake(
  recipientStaticPubB64u: string,
  opts: { keyB64u?: string; room?: string; ephemeralPrivB64u?: string; nonceB64u?: string } = {},
): Handshake {
  const recipientPub = pubFromRaw(unb64u(recipientStaticPubB64u));
  const ephPriv = opts.ephemeralPrivB64u
    ? privFromRaw(unb64u(opts.ephemeralPrivB64u))
    : generateKeyPairSync("x25519").privateKey;
  const shared = derive(diffieHellman({ privateKey: ephPriv, publicKey: recipientPub }));
  const key = opts.keyB64u ? unb64u(opts.keyB64u) : randomBytes(32);
  const room = opts.room ?? "p-" + randomBytes(9).toString("hex");
  const nonce = opts.nonceB64u ? unb64u(opts.nonceB64u) : randomBytes(12);
  const sealed = aesGcmSeal(shared, nonce, Buffer.concat([key, Buffer.from(room, "utf8")]));
  const ephPubRaw = rawOfPrivatePublic(ephPriv);
  return {
    line: `e2e1 ${b64u(ephPubRaw)} ${b64u(nonce)} ${b64u(sealed)}`,
    keyB64u: b64u(key),
    room,
  };
}

/**
 * Recipient side: open an `e2e1 ...` mailbox line with your static X25519
 * private key, recovering the room key and room name.
 */
export function openHandshake(myStaticPrivB64u: string, line: string): { keyB64u: string; room: string } {
  const parts = line.trim().split(" ");
  if (parts.length !== 4 || parts[0] !== "e2e1") {
    throw new Error('not an e2e1 handshake line (expected "e2e1 <eph_pub> <nonce> <sealed>")');
  }
  const [, ephPubB, nonceB, sealedB] = parts as [string, string, string, string];
  const myPriv = privFromRaw(unb64u(myStaticPrivB64u));
  const ephPub = pubFromRaw(unb64u(ephPubB));
  const shared = derive(diffieHellman({ privateKey: myPriv, publicKey: ephPub }));
  const plain = aesGcmOpen(shared, unb64u(nonceB), unb64u(sealedB));
  if (plain.length < 33) throw new Error("sealed payload too short to hold a 32-byte key and a room name");
  return { keyB64u: b64u(plain.subarray(0, 32)), room: plain.subarray(32).toString("utf8") };
}

/** Encrypt one conversation message with the room key K → `<nonce>.<ct>` line. */
export function encryptRoomMessage(keyB64u: string, plaintext: string, nonceB64u?: string): string {
  const key = unb64u(keyB64u);
  const nonce = nonceB64u ? unb64u(nonceB64u) : randomBytes(12);
  const sealed = aesGcmSeal(key, nonce, Buffer.from(plaintext, "utf8"));
  return `${b64u(nonce)}.${b64u(sealed)}`;
}

/** Decrypt one `<nonce>.<ct>` conversation line with the room key K. */
export function decryptRoomMessage(keyB64u: string, line: string): string {
  const dot = line.indexOf(".");
  if (dot < 0) throw new Error('not an e2e room line (expected "<nonce>.<ct>")');
  const nonce = unb64u(line.slice(0, dot));
  const sealed = unb64u(line.slice(dot + 1));
  return aesGcmOpen(unb64u(keyB64u), nonce, sealed).toString("utf8");
}
