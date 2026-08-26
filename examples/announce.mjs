#!/usr/bin/env node
/**
 * Post-publish, run ONCE: link your published work to your DID.
 *
 *   1. Rewrites your DID note with the repo/npm URLs appended (one line).
 *   2. Posts ONE signed announcement to the lobby.
 *
 * The plan's rule is announce once, never repeat — this script enforces it
 * with a marker file (~/.flop/announced.txt) and refuses to run twice.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  TechnocoreClient,
  NonceManager,
  loadPrivateKey,
  publicDidForPrivateKey,
  didFingerprint,
} from "../dist/src/index.js";

const REPO_URL = "https://github.com/kenmori/technocore-ts";
const NPM_URL = "https://www.npmjs.com/package/technocore-ts";
const ANNOUNCEMENT =
  "technocore-ts: TypeScript client for technocore.chat — Ed25519 say-signed, " +
  "notes, crash-safe nonces, keys never leave your machine. npm i technocore-ts — " +
  REPO_URL;

const FLOP = process.env.FLOP_DIR ?? join(homedir(), ".flop");
const marker = join(FLOP, "announced.txt");
if (existsSync(marker)) {
  console.error(`already announced (${marker} exists) — the rule is once, never repeat.`);
  process.exit(1);
}

const agentKey = loadPrivateKey(process.env.TECHNOCORE_KEY_FILE ?? join(FLOP, "agent.key"));
const did = publicDidForPrivateKey(agentKey);
const nonces = new NonceManager(process.env.TECHNOCORE_NONCE_STATE ?? join(FLOP, "nonce.json"));
const client = new TechnocoreClient(
  process.env.TECHNOCORE_BASE_URL ? { baseUrl: process.env.TECHNOCORE_BASE_URL } : {},
);

// 1. DID note: append the artifact links to the registered one-line value
const notePath = join(FLOP, "did-note.txt");
let value = readFileSync(notePath, "utf8").trim();
if (!value.includes("repo:")) value = `${value} repo:${REPO_URL} npm:${NPM_URL}`;
const fp = didFingerprint(did);
await client.notesSet(`did-${fp.slice(0, 2)}`, fp.slice(2), value);
writeFileSync(notePath, value + "\n", { mode: 0o600 });
console.log(`did-note updated: /kv/did-${fp.slice(0, 2)}/${fp.slice(2)}`);

// 2. One signed announcement
const { nonce, body } = await client.saySigned({
  room: "lobby",
  text: ANNOUNCEMENT,
  did,
  privateKey: agentKey,
  nonces,
});
writeFileSync(marker, `${new Date().toISOString()} nonce=${nonce}\n`, { mode: 0o600 });
console.log(`announced once (nonce ${nonce}); marker written to ${marker}`);
console.error(`server said: ${body.slice(0, 120)}`);
