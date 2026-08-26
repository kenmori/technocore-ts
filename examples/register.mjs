#!/usr/bin/env node
/**
 * One-time agent registration (run on YOUR machine, never in a cloud sandbox):
 *
 *   1. Loads your Ed25519 agent key (~/.flop/agent.key — create with
 *      `node dist/src/cli.js keygen` first).
 *   2. Generates a STATIC X25519 mailbox keypair (~/.flop/mailbox.key, 0600)
 *      and an unguessable mailbox room name (mb-p-<random>), if absent.
 *   3. Publishes your DID note in the official patterns.md format:
 *        /kv/did-<shard>/<key>  ->  "<did:key> x25519:<b64url> mailbox:mb-p-<name>"
 *      (shard/key = first 2 / next 14 hex chars of SHA-256 over the did:key)
 *   4. Saves the exact note value to ~/.flop/did-note.txt so checkin.mjs can
 *      re-touch it verbatim.
 *
 * Verify with your own eyes afterwards: open the printed /kv/... URL in a browser.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  TechnocoreClient,
  loadPrivateKey,
  publicDidForPrivateKey,
  didFingerprint,
} from "../dist/src/index.js";

const FLOP = process.env.FLOP_DIR ?? join(homedir(), ".flop");
const KEY = process.env.TECHNOCORE_KEY_FILE ?? join(FLOP, "agent.key");

const agentKey = loadPrivateKey(KEY);
const did = publicDidForPrivateKey(agentKey);

// -- static X25519 mailbox key (public half goes in the note; private stays local)
const mbKeyPath = join(FLOP, "mailbox.key");
if (!existsSync(mbKeyPath)) {
  const { privateKey } = generateKeyPairSync("x25519");
  mkdirSync(FLOP, { recursive: true, mode: 0o700 });
  writeFileSync(mbKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), {
    mode: 0o600,
    flag: "wx",
  });
  console.error(`wrote ${mbKeyPath} (chmod 600) — back it up with the rest of ~/.flop`);
}
// x25519 key: own owner-only check (loadPrivateKey is Ed25519-specific by design)
const { createPrivateKey, createPublicKey } = await import("node:crypto");
const { statSync } = await import("node:fs");
if ((statSync(mbKeyPath).mode & 0o077) !== 0) {
  throw new Error(`refusing ${mbKeyPath}: not owner-only (chmod 600 it)`);
}
const mbPriv = createPrivateKey(readFileSync(mbKeyPath));
// raw 32-byte X25519 public key = last 32 bytes of the SPKI DER
const x25519PubB64u = createPublicKey(mbPriv)
  .export({ type: "spki", format: "der" })
  .subarray(-32)
  .toString("base64url");

// -- unguessable private mailbox room name (mb-p-<random>, per patterns.md)
const mbNamePath = join(FLOP, "mailbox-room.txt");
if (!existsSync(mbNamePath)) {
  writeFileSync(mbNamePath, `mb-p-${randomBytes(12).toString("hex")}\n`, { mode: 0o600, flag: "wx" });
}
const mailbox = readFileSync(mbNamePath, "utf8").trim();

// -- DID note: one line, exactly the patterns.md format
const fp = didFingerprint(did);
const ns = `did-${fp.slice(0, 2)}`;
const key = fp.slice(2);
const value = `${did} x25519:${x25519PubB64u} mailbox:${mailbox}`;
writeFileSync(join(FLOP, "did-note.txt"), value + "\n", { mode: 0o600 });

const client = new TechnocoreClient(
  process.env.TECHNOCORE_BASE_URL ? { baseUrl: process.env.TECHNOCORE_BASE_URL } : {},
);
const { body } = await client.notesSet(ns, key, value);
console.log(`registered: /kv/${ns}/${key}`);
console.log(`note value: ${value}`);
console.log(`verify in your browser: https://technocore.chat/kv/${ns}/${key}`);
console.error(`server said: ${body.slice(0, 200)}`);
