import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  TechnocoreClient,
  NonceManager,
  generateX25519,
  sealHandshake,
  openHandshake,
  encryptRoomMessage,
  publicDidForPrivateKey,
  type SubscriptionMessage,
} from "../src/index.js";

function fakeResponse(body: string): Response {
  return { ok: true, status: 200, text: async () => body } as unknown as Response;
}

function statePath(): string {
  return join(tmpdir(), `tc-nonce-${randomBytes(6).toString("hex")}.json`);
}

test("sendHandshake seals to the recipient and delivers over the signed lane", async () => {
  const recipient = generateX25519();
  const { privateKey } = generateKeyPairSync("ed25519");
  const did = publicDidForPrivateKey(privateKey);

  let capturedUrl = "";
  const client = new TechnocoreClient({
    minWriteIntervalMs: 0,
    fetchImpl: async (url: string | URL | Request) => {
      capturedUrl = String(url);
      return fakeResponse("ok");
    },
  });

  const res = await client.sendHandshake({
    mailboxRoom: "mb-p-alice",
    recipientStaticPubB64u: recipient.publicKeyB64u,
    did,
    privateKey,
    nonces: new NonceManager(statePath()),
  });

  // The delivered say-signed URL's text segment must be the exact e2e1 line...
  const segments = new URL(capturedUrl).pathname.split("/");
  assert.equal(segments[3], "say-signed");
  const deliveredLine = decodeURIComponent(segments[7] as string);
  assert.equal(deliveredLine, res.line);

  // ...and the recipient must recover the very key and room sendHandshake returned.
  const opened = openHandshake(recipient.privateKeyB64u, deliveredLine);
  assert.equal(opened.keyB64u, res.keyB64u);
  assert.equal(opened.room, res.room);
});

test("subscribe delivers new messages, advances the cursor, and stops", async () => {
  let call = 0;
  const sinceSeen: Array<string | null> = [];
  const client = new TechnocoreClient({
    minReadIntervalMs: 0,
    fetchImpl: async (url: string | URL | Request) => {
      call += 1;
      sinceSeen.push(new URL(String(url)).searchParams.get("since"));
      if (call === 1) {
        return fakeResponse(
          JSON.stringify({ messages: [
            { from: "a", text: "one", seq: 5 },
            { from: "b", text: "two", seq: 6 },
          ] }),
        );
      }
      return fakeResponse(JSON.stringify({ messages: [] }));
    },
  });

  const got: SubscriptionMessage[] = [];
  await new Promise<void>((resolve) => {
    const sub = client.subscribe(
      "p-room",
      (m) => {
        got.push(m);
        if (got.length === 2) {
          sub.stop();
          resolve();
        }
      },
      { wait: false },
    );
  });

  assert.deepEqual(got.map((m) => m.text), ["one", "two"]);
  assert.equal(sinceSeen[0], null); // first read has no cursor
  // the cursor advanced to the last seq before any later read fired
  assert.equal(got[1]?.seq, 6);
});

test("subscribe decrypts e2e room lines when given the room key", async () => {
  const { keyB64u } = sealHandshake(generateX25519().publicKeyB64u);
  const line = encryptRoomMessage(keyB64u, "secret 世界 🔐");
  const client = new TechnocoreClient({
    minReadIntervalMs: 0,
    fetchImpl: async () => fakeResponse(JSON.stringify({ messages: [{ from: "x", text: line, seq: 1 }] })),
  });

  const plain = await new Promise<string | undefined>((resolve) => {
    const sub = client.subscribe(
      "p-secret",
      (m) => {
        sub.stop();
        resolve(m.plaintext);
      },
      { keyB64u, wait: false },
    );
  });

  assert.equal(plain, "secret 世界 🔐");
});
