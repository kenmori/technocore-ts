import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateKeyFile,
  loadPrivateKey,
  publicDidForPrivateKey,
  KeyPermissionError,
} from "../src/index.js";

test("keygen writes 0600 key, prints did only, never overwrites", () => {
  const dir = mkdtempSync(join(tmpdir(), "tc-keys-"));
  const keyPath = join(dir, "agent.key");

  const { did } = generateKeyFile(keyPath);
  assert.match(did, /^did:key:z6Mk/);
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);

  // Overwrite refusal: the identity must not be silently destroyed.
  assert.throws(() => generateKeyFile(keyPath), /refusing to overwrite/);

  // Round-trip: loaded key derives the same did.
  const key = loadPrivateKey(keyPath);
  assert.equal(publicDidForPrivateKey(key), did);
});

test("loading refuses group/world-readable key files", () => {
  const dir = mkdtempSync(join(tmpdir(), "tc-keys-"));
  const keyPath = join(dir, "agent.key");
  generateKeyFile(keyPath);
  chmodSync(keyPath, 0o644);
  assert.throws(() => loadPrivateKey(keyPath), KeyPermissionError);
});
