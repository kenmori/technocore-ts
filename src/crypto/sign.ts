import {
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { rawPublicKeyFromDid } from "./did.js";

/**
 * Technocore signed-message construction.
 *
 * The signature covers the UTF-8 bytes of `<room>|<nonce>|<text>` where
 * `text` has already been through the single-line sweep (see core/sweep.ts).
 * Output is base64url without padding — exactly 86 chars for a 64-byte
 * Ed25519 signature.
 */
export function signingPayload(room: string, nonce: string, sweptText: string): Buffer {
  return Buffer.from(`${room}|${nonce}|${sweptText}`, "utf8");
}

export function signMessage(
  privateKey: KeyObject,
  room: string,
  nonce: string,
  sweptText: string,
): string {
  const sig = edSign(null, signingPayload(room, nonce, sweptText), privateKey);
  const b64u = sig.toString("base64url");
  if (b64u.length !== 86 || b64u.includes("=")) {
    // Never include key material in errors; lengths only.
    throw new Error(`unexpected signature encoding (len=${b64u.length}); expected 86-char unpadded base64url`);
  }
  return b64u;
}

/** Verify a signature against a did:key (useful in tests and for auditing). */
export function verifyMessage(
  did: string,
  room: string,
  nonce: string,
  sweptText: string,
  sigB64u: string,
): boolean {
  const raw = rawPublicKeyFromDid(did);
  // Rebuild an SPKI KeyObject from the raw key: fixed 12-byte Ed25519 header.
  const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
  const publicKey = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
  const sig = Buffer.from(sigB64u, "base64url");
  if (sig.length !== 64) return false;
  return edVerify(null, signingPayload(room, nonce, sweptText), publicKey, sig);
}

/**
 * Note (kv) signing: the payload is the UTF-8 bytes of
 * `<namespace>|<key>|<nonce>|<value>` (used for room-owners / room-allow
 * style protected notes). `value` comes last, so pipes inside it are
 * unambiguous; namespace/key/nonce must not contain pipes.
 */
export function noteSigningPayload(
  namespace: string,
  key: string,
  nonce: string,
  value: string,
): Buffer {
  for (const [what, s] of [["namespace", namespace], ["key", key], ["nonce", nonce]] as const) {
    if (s.includes("|")) throw new Error(`${what} must not contain "|"`);
  }
  return Buffer.from(`${namespace}|${key}|${nonce}|${value}`, "utf8");
}

export function signNote(
  privateKey: KeyObject,
  namespace: string,
  key: string,
  nonce: string,
  value: string,
): string {
  const sig = edSign(null, noteSigningPayload(namespace, key, nonce, value), privateKey);
  const b64u = sig.toString("base64url");
  if (b64u.length !== 86 || b64u.includes("=")) {
    throw new Error(`unexpected signature encoding (len=${b64u.length}); expected 86-char unpadded base64url`);
  }
  return b64u;
}

export function verifyNote(
  did: string,
  namespace: string,
  key: string,
  nonce: string,
  value: string,
  sigB64u: string,
): boolean {
  const raw = rawPublicKeyFromDid(did);
  const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
  const publicKey = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
  const sig = Buffer.from(sigB64u, "base64url");
  if (sig.length !== 64) return false;
  return edVerify(null, noteSigningPayload(namespace, key, nonce, value), publicKey, sig);
}
