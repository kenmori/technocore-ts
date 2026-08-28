import { test } from "node:test";
import assert from "node:assert/strict";
import {
  sealHandshake,
  openHandshake,
  encryptRoomMessage,
  decryptRoomMessage,
  generateX25519,
  E2E_SPEC_VERIFIED,
} from "../src/index.js";

/**
 * The two vectors below were produced by the Python `cryptography` library —
 * the reference the technocore-e2e-v1 spec is written against — with fixed
 * inputs (A static priv = 0x00..0x1f, ephemeral = 0x20..0x3f, K = 0x64..0x83,
 * handshake nonce = 0x00..0x0b, message nonce = 0x14..0x1f). Decrypting them
 * here pins byte-for-byte interop: HKDF salt handling, the info string, and
 * AES-GCM tag placement all have to match, or these fail.
 */
const A_STATIC_PRIV = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const A_STATIC_PUB = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8";
const HANDSHAKE_LINE =
  "e2e1 NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ AAECAwQFBgcICQoL " +
  "ztTwtbgm3JVLMLdKAmrv3Ul1Lu46cTgrn5R9Gv5RbOcVFR9aBCd3nRZYsKwsOsDLsH0-q5b0MmzLTTX5993Rn-yy";
const EXPECT_K = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM";
const EXPECT_ROOM = "p-deadbeefcafe0001";
const MSG_LINE = "FBUWFxgZGhscHR4f.cbWYXP6h4babz7bOfV8_lQlD1A7nFqb-vPciOoG-bE47F1grg_SZZA";
const EXPECT_PLAINTEXT = "こんにちは e2e 🎉";

test("interop: opens a handshake sealed by the Python reference", () => {
  assert.equal(E2E_SPEC_VERIFIED, true);
  const { keyB64u, room } = openHandshake(A_STATIC_PRIV, HANDSHAKE_LINE);
  assert.equal(keyB64u, EXPECT_K);
  assert.equal(room, EXPECT_ROOM);
});

test("interop: decrypts a room message sealed by the Python reference", () => {
  assert.equal(decryptRoomMessage(EXPECT_K, MSG_LINE), EXPECT_PLAINTEXT);
});

test("interop: our own seal reproduces the reference line byte-for-byte", () => {
  // Same fixed inputs the vector used → must produce the identical e2e1 line.
  const h = sealHandshake(A_STATIC_PUB, {
    ephemeralPrivB64u: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8", // 0x20..0x3f
    keyB64u: EXPECT_K,
    room: EXPECT_ROOM,
    nonceB64u: "AAECAwQFBgcICQoL", // 0x00..0x0b
  });
  assert.equal(h.line, HANDSHAKE_LINE);
  assert.equal(h.keyB64u, EXPECT_K);
  assert.equal(h.room, EXPECT_ROOM);
});

test("round-trip: seal → open recovers key and room", () => {
  const alice = generateX25519();
  const h = sealHandshake(alice.publicKeyB64u);
  const opened = openHandshake(alice.privateKeyB64u, h.line);
  assert.equal(opened.keyB64u, h.keyB64u);
  assert.equal(opened.room, h.room);
});

test("round-trip: encrypt → decrypt a conversation message (unicode)", () => {
  const { keyB64u } = sealHandshake(generateX25519().publicKeyB64u);
  const line = encryptRoomMessage(keyB64u, "hello 世界 🎉 | with | pipes");
  assert.equal(line.split(".").length, 2);
  assert.equal(decryptRoomMessage(keyB64u, line), "hello 世界 🎉 | with | pipes");
});

test("wrong recipient key cannot open the handshake", () => {
  const alice = generateX25519();
  const mallory = generateX25519();
  const h = sealHandshake(alice.publicKeyB64u);
  assert.throws(() => openHandshake(mallory.privateKeyB64u, h.line));
});

test("tampered ciphertext is rejected by the GCM tag", () => {
  const { keyB64u } = sealHandshake(generateX25519().publicKeyB64u);
  const line = encryptRoomMessage(keyB64u, "authentic");
  const [n, ct] = line.split(".");
  const bad = Buffer.from(ct as string, "base64url");
  bad.writeUInt8(bad.readUInt8(0) ^ 0x01, 0);
  assert.throws(() => decryptRoomMessage(keyB64u, `${n}.${bad.toString("base64url")}`));
});

test("malformed lines are rejected clearly", () => {
  assert.throws(() => openHandshake(A_STATIC_PRIV, "not-a-handshake"), /e2e1 handshake/);
  assert.throws(() => decryptRoomMessage(EXPECT_K, "no-dot-here"), /e2e room line/);
});
