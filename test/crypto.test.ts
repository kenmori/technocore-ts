import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  base58btcEncode,
  base58btcDecode,
  didFromPublicKey,
  rawPublicKey,
  rawPublicKeyFromDid,
  didFingerprint,
  didNotePath,
  signMessage,
  verifyMessage,
  signingPayload,
} from "../src/index.js";

test("base58btc round-trips and preserves leading zeros", () => {
  assert.equal(base58btcEncode(Uint8Array.from([])), "");
  assert.equal(base58btcEncode(Uint8Array.from([0, 0])), "11");
  const cases = [
    Uint8Array.from([0]),
    Uint8Array.from([0, 1, 2, 3]),
    Uint8Array.from([255, 254, 253]),
    Uint8Array.from(Array.from({ length: 34 }, (_, i) => (i * 7) % 256)),
  ];
  for (const c of cases) {
    assert.deepEqual(base58btcDecode(base58btcEncode(c)), c);
  }
  assert.throws(() => base58btcDecode("0OIl"), /invalid base58/);
});

test("did:key derivation: z6Mk prefix and exact round-trip", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  assert.match(did, /^did:key:z6Mk/);
  assert.deepEqual(rawPublicKeyFromDid(did), rawPublicKey(publicKey));
});

test("rawPublicKeyFromDid rejects non-ed25519 material", () => {
  assert.throws(() => rawPublicKeyFromDid("did:key:abc"), /base58btc did:key/);
  // valid base58 but wrong multicodec
  const bogus = "did:key:z" + base58btcEncode(Uint8Array.from([0x12, 0x00, ...new Array(32).fill(1)]));
  assert.throws(() => rawPublicKeyFromDid(bogus), /Ed25519/);
});

test("fingerprint is 16 lowercase hex chars, note path splits 2/14", () => {
  const did = "did:key:z6MkexampleExampleExampleExampleExampleExam";
  const fp = didFingerprint(did);
  assert.match(fp, /^[0-9a-f]{16}$/);
  const path = didNotePath(did);
  assert.equal(path, `/kv/did-${fp.slice(0, 2)}/${fp.slice(2)}`);
});

test("signature: 86-char unpadded base64url, verifies, tamper fails", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  const sig = signMessage(privateKey, "lobby", "1756170000000", "hello world");
  assert.equal(sig.length, 86);
  assert.ok(!sig.includes("="));
  assert.ok(verifyMessage(did, "lobby", "1756170000000", "hello world", sig));
  assert.ok(!verifyMessage(did, "lobby", "1756170000000", "hello worle", sig));
  assert.ok(!verifyMessage(did, "lobby", "1756170000001", "hello world", sig));
  assert.ok(!verifyMessage(did, "other", "1756170000000", "hello world", sig));
});

test("signing payload is exactly room|nonce|text in UTF-8", () => {
  const p = signingPayload("lobby", "123", "日本語 text");
  assert.deepEqual(p, Buffer.from("lobby|123|日本語 text", "utf8"));
});
