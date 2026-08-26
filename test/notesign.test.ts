import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  didFromPublicKey,
  signNote,
  verifyNote,
  noteSigningPayload,
} from "../src/index.js";

test("note payload is namespace|key|nonce|value in UTF-8, value last", () => {
  const p = noteSigningPayload("did-ab", "cdef", "123", "v1 | with pipe");
  assert.deepEqual(p, Buffer.from("did-ab|cdef|123|v1 | with pipe", "utf8"));
});

test("note payload rejects pipes outside value", () => {
  assert.throws(() => noteSigningPayload("a|b", "k", "1", "v"), /namespace/);
  assert.throws(() => noteSigningPayload("ns", "k|k", "1", "v"), /key/);
  assert.throws(() => noteSigningPayload("ns", "k", "1|1", "v"), /nonce/);
});

test("note signature: 86-char unpadded base64url, verifies, tamper fails", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  const sig = signNote(privateKey, "did-ab", "cdef0123456789", "1756170000000", "did:key:z6Mk... mailbox:mb-p-x");
  assert.equal(sig.length, 86);
  assert.ok(!sig.includes("="));
  assert.ok(verifyNote(did, "did-ab", "cdef0123456789", "1756170000000", "did:key:z6Mk... mailbox:mb-p-x", sig));
  assert.ok(!verifyNote(did, "did-ab", "cdef0123456789", "1756170000000", "tampered", sig));
  assert.ok(!verifyNote(did, "did-ac", "cdef0123456789", "1756170000000", "did:key:z6Mk... mailbox:mb-p-x", sig));
});
