import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  TechnocoreClient,
  signMessage,
  publicDidForPrivateKey,
  rawJsonField,
  parseExport,
  findSignedRecord,
  verifyEvidence,
  evidenceFromRecord,
  captureEvidence,
  type Evidence,
} from "../src/index.js";

const { privateKey } = generateKeyPairSync("ed25519");
const DID = publicDidForPrivateKey(privateKey);

/** One stored line in the server's field order: seq, ts, from, text, nonce, sig. */
function record(seq: number, text: string, nonce: string, room = "lobby"): string {
  const sig = signMessage(privateKey, room, nonce, text);
  return JSON.stringify({ seq, ts: "2026-09-01T00:00:00.000000Z", from: DID, text, nonce: 0 })
    .replace('"nonce":0', `"nonce":${nonce}`)
    .replace(/}$/, `,"sig":"${sig}"}`);
}

function exportingClient(ndjson: string, generation = "3"): TechnocoreClient {
  const fetchImpl = (async () =>
    ({
      ok: true,
      status: 200,
      text: async () => ndjson,
      headers: new Headers({ "x-room-generation": generation }),
    }) as unknown as Response) as unknown as typeof fetch;
  return new TechnocoreClient({ fetchImpl, minReadIntervalMs: 0, minWriteIntervalMs: 0 });
}

test("a captured record verifies offline, with no network and no server", async () => {
  const line = record(41, "hello", "1788179483510");
  const ev = await captureEvidence(exportingClient(line + "\n"), {
    room: "lobby",
    seq: 41,
  });
  assert.equal(ev.did, DID);
  assert.equal(ev.nonce, "1788179483510");
  assert.equal(ev.generation, 3);
  assert.equal(ev.origin, "https://technocore.chat");
  // The whole point: nothing above is consulted again. Only the five signed fields are.
  assert.equal(verifyEvidence(ev), true);
});

test("a 19-digit nonce survives capture, because the literal is never a JS number", async () => {
  // 9223372036854775807 is the int64 ceiling the server's 1-19 digit rule allows, and it
  // is past 2^53: JSON.parse would round it to ...5808 and the signature would not verify.
  const nonce = "9223372036854775807";
  assert.notEqual(String(JSON.parse(`{"n":${nonce}}`).n), nonce, "premise: JSON.parse loses it");

  const ev = await captureEvidence(exportingClient(record(7, "big nonce", nonce) + "\n"), {
    room: "lobby",
    seq: 7,
  });
  assert.equal(ev.nonce, nonce);
  assert.equal(verifyEvidence(ev), true);
});

test("a message body that spoofs a nonce field cannot displace the real one", async () => {
  // `text` is stored BEFORE `nonce`, so a regex over the line would match this first.
  const line = record(9, 'look at me: "nonce":1', "1788179483511");
  const [rec] = parseExport(line + "\n");
  assert.equal(rec?.nonce, "1788179483511");
  assert.equal(verifyEvidence(evidenceFromRecord(rec!, { origin: "x", room: "lobby", generation: 1 })), true);
});

test("rawJsonField answers for top-level keys only", () => {
  const line = '{"seq":1,"text":"{\\"nonce\\":1}","nonce":42,"nested":{"nonce":99}}';
  assert.equal(rawJsonField(line, "nonce"), "42");
  assert.equal(rawJsonField(line, "seq"), "1");
  assert.equal(rawJsonField(line, "absent"), undefined);
});

test("a torn final line costs only itself", () => {
  const good = record(1, "kept", "100");
  const records = parseExport(`${good}\n{"seq":2,"ts":"t","from":"${DID}","te`);
  assert.equal(records.length, 1);
  assert.equal(records[0]?.seq, 1);
});

test("unsigned records are never offered as evidence", () => {
  const unsigned = JSON.stringify({ seq: 5, ts: "t", from: "alice", text: "hi" });
  const records = parseExport(unsigned + "\n");
  assert.equal(records.length, 1);
  assert.equal(findSignedRecord(records, { seq: 5 }), undefined);
  assert.throws(
    () => evidenceFromRecord(records[0]!, { origin: "x", room: "lobby", generation: 1 }),
    /not signed/,
  );
});

test("an ambiguous selector yields nothing rather than a guess", () => {
  const records = parseExport(`${record(1, "a", "10")}\n${record(2, "b", "20")}\n`);
  assert.equal(findSignedRecord(records, { did: DID }), undefined);
  assert.equal(findSignedRecord(records, { did: DID, seq: 2 })?.seq, 2);
  assert.throws(() => findSignedRecord(records, {}), /at least one/);
});

test("tampering with any signed field fails the check", () => {
  const rec = parseExport(record(3, "original", "500") + "\n")[0]!;
  const ctx = { origin: "x", room: "lobby", generation: 1 };
  const ev = evidenceFromRecord(rec, ctx);
  assert.equal(verifyEvidence(ev), true);
  for (const patch of [
    { text: "edited" },
    { nonce: "501" },
    { room: "other" },
    { sig: "A".repeat(85) + "Q" },
  ] as Partial<Evidence>[]) {
    assert.equal(verifyEvidence({ ...ev, ...patch }), false, JSON.stringify(patch));
  }
});

test("a record that left the ring is a thrown error, not an unverified file", async () => {
  await assert.rejects(
    captureEvidence(exportingClient(record(1, "still here", "10") + "\n"), {
      room: "lobby",
      seq: 999,
    }),
    /already have left the ring/,
  );
});

test("exportRoom reports generation 0 when the server sends no header", async () => {
  const fetchImpl = (async () =>
    ({ ok: true, status: 200, text: async () => "", headers: new Headers() }) as unknown as Response) as unknown as typeof fetch;
  const client = new TechnocoreClient({ fetchImpl, minReadIntervalMs: 0 });
  assert.deepEqual(await client.exportRoom("lobby"), { generation: 0, ndjson: "" });
});
