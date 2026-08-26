import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TechnocoreClient,
  NonceManager,
  didFromPublicKey,
  verifyMessage,
} from "../src/index.js";

function fakeFetch(capture: { url?: string }): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    capture.url = String(input);
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
}

function newClient(capture: { url?: string }): TechnocoreClient {
  return new TechnocoreClient({
    fetchImpl: fakeFetch(capture),
    minReadIntervalMs: 0,
    minWriteIntervalMs: 0,
  });
}

test("readRoom builds /r/<room>?format=json and encodes the room", async () => {
  const cap: { url?: string } = {};
  await newClient(cap).readRoom("lobby");
  assert.equal(cap.url, "https://technocore.chat/r/lobby?format=json");
  await newClient(cap).readRoom("a b", { since: "42" });
  assert.equal(cap.url, "https://technocore.chat/r/a%20b?format=json&since=42");
});

test("saySigned: URL components round-trip and the signature verifies", async () => {
  const cap: { url?: string } = {};
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  const nonces = new NonceManager(join(mkdtempSync(join(tmpdir(), "tc-cl-")), "n.json"));

  const text = "hello\nworld | 日本語 100%";
  const { swept, nonce } = await newClient(cap).saySigned({
    room: "lobby",
    text,
    did,
    privateKey,
    nonces,
  });

  assert.equal(swept, "hello world | 日本語 100%");
  const url = new URL(cap.url!);
  const parts = url.pathname.split("/"); // ["", "r", room, "say-signed", did, sig, nonce, text]
  assert.equal(parts[1], "r");
  assert.equal(parts[2], "lobby");
  assert.equal(parts[3], "say-signed");
  assert.equal(decodeURIComponent(parts[4]!), did);
  const sig = parts[5]!;
  assert.equal(parts[6], nonce);
  const sentText = decodeURIComponent(parts[7]!);
  assert.equal(sentText, swept);
  // The signature must verify over exactly what was sent.
  assert.ok(verifyMessage(did, "lobby", nonce, sentText, sig));
});

test("saySigned rejects rooms containing | or /", async () => {
  const cap: { url?: string } = {};
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  const nonces = new NonceManager(join(mkdtempSync(join(tmpdir(), "tc-cl-")), "n.json"));
  for (const room of ["a|b", "a/b"]) {
    await assert.rejects(
      newClient(cap).saySigned({ room, text: "x", did, privateKey, nonces }),
      /must not contain/,
    );
  }
});

test("saySigned rejects text that sweeps to empty", async () => {
  const cap: { url?: string } = {};
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const did = didFromPublicKey(publicKey);
  const nonces = new NonceManager(join(mkdtempSync(join(tmpdir(), "tc-cl-")), "n.json"));
  await assert.rejects(
    newClient(cap).saySigned({ room: "lobby", text: " \n\t ", did, privateKey, nonces }),
    /empty after/,
  );
});

test("non-2xx responses raise without echoing the body", async () => {
  const failFetch = (async () =>
    new Response("<html>attacker controlled error page</html>", { status: 500 })) as typeof fetch;
  const c = new TechnocoreClient({ fetchImpl: failFetch, minReadIntervalMs: 0 });
  await assert.rejects(c.readRoom("lobby"), (e: Error) => {
    assert.match(e.message, /HTTP 500/);
    assert.ok(!e.message.includes("attacker"));
    return true;
  });
});

test("notesSet is SPEC-PENDING and refuses to guess", () => {
  const c = new TechnocoreClient({});
  assert.throws(() => c.notesSet(), /SPEC-PENDING/);
});
