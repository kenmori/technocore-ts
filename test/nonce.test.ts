import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NonceManager } from "../src/index.js";

function tmpState(): string {
  return join(mkdtempSync(join(tmpdir(), "tc-nonce-")), "nonce.json");
}

test("same-millisecond writes get strictly increasing nonces", () => {
  const t = 1756170000000;
  const nm = new NonceManager(tmpState(), () => t);
  assert.equal(nm.next("lobby"), "1756170000000");
  assert.equal(nm.next("lobby"), "1756170000001"); // clock frozen -> last+1
  assert.equal(nm.next("lobby"), "1756170000002");
});

test("clock rollback never reuses or decreases", () => {
  let t = 1756170000000;
  const nm = new NonceManager(tmpState(), () => t);
  nm.next("lobby");
  t -= 60_000; // clock jumps backwards a minute
  assert.equal(nm.next("lobby"), "1756170000001");
});

test("rooms are independent", () => {
  const t = 1756170000000;
  const nm = new NonceManager(tmpState(), () => t);
  assert.equal(nm.next("lobby"), "1756170000000");
  assert.equal(nm.next("dev"), "1756170000000");
});

test("state survives restart (persisted before use)", () => {
  const state = tmpState();
  const t = 1756170000000;
  const a = new NonceManager(state, () => t);
  a.next("lobby");
  a.next("lobby");
  // New instance with the clock behind the persisted value: continue, not repeat.
  const b = new NonceManager(state, () => t - 5000);
  assert.equal(b.next("lobby"), "1756170000002");
});

test("corrupt state file falls back to clock", () => {
  const state = tmpState();
  writeFileSync(state, "not json {");
  const nm = new NonceManager(state, () => 1756170000000);
  assert.equal(nm.next("lobby"), "1756170000000");
});
