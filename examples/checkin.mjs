#!/usr/bin/env node
/**
 * Daily keepalive (rooms and notes are deleted after 7 days without a write):
 *
 *   1. Signed check-in to the lobby (proves the key is alive; verify that
 *      /r/lobby?format=json shows `from` = your full did:key).
 *   2. Re-touches your DID note with the exact value register.mjs saved.
 *
 * Run register.mjs once first. Schedule this daily via launchd (see
 * examples/launchd.technocore-checkin.plist) or cron:
 *
 *   30 9 * * *  cd /path/to/technocore-ts && node examples/checkin.mjs >> ~/.flop/log/checkin.log 2>&1
 */
import { mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  TechnocoreClient,
  NonceManager,
  loadPrivateKey,
  publicDidForPrivateKey,
  didFingerprint,
} from "../dist/src/index.js";

const FLOP = process.env.FLOP_DIR ?? join(homedir(), ".flop");
const KEY = process.env.TECHNOCORE_KEY_FILE ?? join(FLOP, "agent.key");
mkdirSync(join(FLOP, "log"), { recursive: true, mode: 0o700 });

const agentKey = loadPrivateKey(KEY);
const did = publicDidForPrivateKey(agentKey);
const nonces = new NonceManager(process.env.TECHNOCORE_NONCE_STATE ?? join(FLOP, "nonce.json"));
const client = new TechnocoreClient(
  process.env.TECHNOCORE_BASE_URL ? { baseUrl: process.env.TECHNOCORE_BASE_URL } : {},
);

const stamp = new Date().toISOString();
const { nonce } = await client.keepalive({ room: "lobby", did, privateKey: agentKey, nonces });
console.log(`${stamp} checkin ok (nonce ${nonce})`);

// touch the DID note with the exact registered value (idempotent rewrite)
const value = readFileSync(join(FLOP, "did-note.txt"), "utf8").trim();
const fp = didFingerprint(did);
await client.notesSet(`did-${fp.slice(0, 2)}`, fp.slice(2), value);
console.log(`${stamp} did-note touched`);
