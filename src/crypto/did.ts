import { createHash, type KeyObject } from "node:crypto";
import { base58btcEncode, base58btcDecode } from "./base58.js";

/**
 * did:key for Ed25519 public keys.
 *
 * Layout: "did:key:z" + base58btc( 0xed 0x01 || 32-byte raw public key )
 * The multicodec prefix 0xed01 is ed25519-pub; "z" is the multibase
 * prefix for base58btc. Ed25519 did:keys therefore always start "did:key:z6Mk".
 */
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01]);

/** Extract the raw 32-byte Ed25519 public key from a node KeyObject. */
export function rawPublicKey(publicKey: KeyObject): Uint8Array {
  // SPKI DER for Ed25519 is a fixed 12-byte header followed by the raw key.
  const der = publicKey.export({ type: "spki", format: "der" });
  const raw = new Uint8Array(der.subarray(der.length - 32));
  if (der.length !== 44) {
    throw new Error(`unexpected SPKI length ${der.length}; not an Ed25519 key?`);
  }
  return raw;
}

export function didFromRawPublicKey(raw: Uint8Array): string {
  if (raw.length !== 32) throw new Error(`raw Ed25519 public key must be 32 bytes, got ${raw.length}`);
  const prefixed = new Uint8Array(2 + raw.length);
  prefixed.set(MULTICODEC_ED25519_PUB, 0);
  prefixed.set(raw, 2);
  return "did:key:z" + base58btcEncode(prefixed);
}

export function didFromPublicKey(publicKey: KeyObject): string {
  return didFromRawPublicKey(rawPublicKey(publicKey));
}

/** Parse a did:key back to the raw 32-byte Ed25519 public key. Throws on anything else. */
export function rawPublicKeyFromDid(did: string): Uint8Array {
  if (!did.startsWith("did:key:z")) throw new Error("not a base58btc did:key");
  const bytes = base58btcDecode(did.slice("did:key:z".length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("did:key is not an Ed25519 key (expected multicodec 0xed01 + 32 bytes)");
  }
  return bytes.slice(2);
}

/**
 * Technocore DID note fingerprint: first 16 lowercase hex chars of
 * SHA-256 over the did:key string (UTF-8). Note path is
 * /kv/did-<first 2>/<remaining 14>.
 */
export function didFingerprint(did: string): string {
  return createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16);
}

export function didNotePath(did: string): string {
  const fp = didFingerprint(did);
  return `/kv/did-${fp.slice(0, 2)}/${fp.slice(2)}`;
}
