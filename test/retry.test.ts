import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  TechnocoreClient,
  NonceManager,
  publicDidForPrivateKey,
  WriteMayHaveLandedError,
} from "../src/index.js";

const ok = (body = "{}") =>
  ({ ok: true, status: 200, text: async () => body, headers: new Headers() }) as unknown as Response;
const refuse = (status: number, headers: Record<string, string> = {}) =>
  ({ ok: false, status, text: async () => "refused", headers: new Headers(headers) }) as unknown as Response;

/** A client with no throttling and no real backoff, so tests do not sleep. */
function client(fetchImpl: unknown, opts = {}) {
  return new TechnocoreClient({
    fetchImpl: fetchImpl as typeof fetch,
    minReadIntervalMs: 0,
    minWriteIntervalMs: 0,
    retryBaseMs: 1,
    ...opts,
  });
}

function statePath(): string {
  return join(tmpdir(), `tc-nonce-${randomBytes(6).toString("hex")}.json`);
}

test("a transport failure is retried — the case a status-code retry cannot see", async () => {
  const seen: string[] = [];
  let calls = 0;
  const c = client(async (url: string) => {
    seen.push(url);
    if (++calls < 3) throw Object.assign(new Error("fetch failed"), { code: "ECONNRESET" });
    return ok('{"messages":[]}');
  });
  assert.equal(await c.readRoom("lobby"), '{"messages":[]}');
  assert.equal(calls, 3);
  assert.equal(new Set(seen).size, 1, "a retry resends the identical URL");
});

test("a per-attempt deadline turns a hang into a retryable failure", async () => {
  let calls = 0;
  const c = client(async (_url: string, init: RequestInit) => {
    calls++;
    // Never answers on its own: only the caller's signal ends it, as a hung socket
    // does. Without a deadline this await would sit for undici's 300 s default.
    return new Promise<Response>((resolve, reject) => {
      if (calls > 1) return resolve(ok("late but fine"));
      // A ref'd timer, because AbortSignal.timeout's own timer is unref'd: with
      // nothing else pending the loop would drain before the deadline fired. A
      // real socket holds the loop open, so this stands in for one.
      const socket = setTimeout(() => reject(new Error("never answered")), 5000);
      init.signal?.addEventListener("abort", () => {
        clearTimeout(socket);
        reject(new Error("TimeoutError"));
      });
    });
  }, { requestTimeoutMs: 20 });
  assert.equal(await c.readRoom("lobby"), "late but fine");
  assert.equal(calls, 2);
});

test("503 is retried, 400 is not", async () => {
  let calls = 0;
  const flaky = client(async () => (++calls < 3 ? refuse(503) : ok("recovered")));
  assert.equal(await flaky.readRoom("lobby"), "recovered");
  assert.equal(calls, 3);

  let hard = 0;
  const bad = client(async () => {
    hard++;
    return refuse(400);
  });
  await assert.rejects(bad.readRoom("lobby"), /HTTP 400/);
  assert.equal(hard, 1, "a 4xx is the venue's considered answer");
});

test("Retry-After is honoured over the backoff", async () => {
  const waits: number[] = [];
  let calls = 0;
  const started = Date.now();
  const c = client(async () => {
    waits.push(Date.now() - started);
    return ++calls < 2 ? refuse(429, { "retry-after": "0.05" }) : ok("through");
  }, { retryBaseMs: 5000 });
  assert.equal(await c.readRoom("lobby"), "through");
  assert.ok(waits[1]! < 1000, `waited ${waits[1]}ms — the 5s backoff was used instead`);
});

test("attempts are bounded and the transport cause survives", async () => {
  let calls = 0;
  const c = client(async () => {
    calls++;
    throw new Error("ECONNRESET");
  }, { maxRetries: 2 });
  await assert.rejects(c.readRoom("lobby"), (err: Error) => {
    assert.match(err.message, /failed after 3 attempts/);
    assert.match((err.cause as Error).message, /ECONNRESET/);
    return true;
  });
  assert.equal(calls, 3);
});

test("a retried write refused for its nonce is named, not reported as a plain failure", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  let calls = 0;
  const c = client(async () => {
    // First attempt dies in transport after the venue took it; the resend is then
    // refused because the nonce was already spent.
    if (++calls === 1) throw new Error("ECONNRESET");
    return refuse(403);
  });
  await assert.rejects(
    c.saySigned({
      room: "lobby",
      text: "hello",
      did: publicDidForPrivateKey(privateKey),
      privateKey,
      nonces: new NonceManager(statePath()),
    }),
    (err: Error) => {
      assert.ok(err instanceof WriteMayHaveLandedError, `got ${err.name}`);
      assert.equal((err as WriteMayHaveLandedError).status, 403);
      assert.match(err.message, /may have\s+landed/);
      return true;
    },
  );
});

test("a first-attempt 403 is an ordinary refusal, not an ambiguous one", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const c = client(async () => refuse(403));
  await assert.rejects(
    c.saySigned({
      room: "lobby",
      text: "hello",
      did: publicDidForPrivateKey(privateKey),
      privateKey,
      nonces: new NonceManager(statePath()),
    }),
    (err: Error) => {
      assert.ok(!(err instanceof WriteMayHaveLandedError));
      assert.match(err.message, /HTTP 403/);
      return true;
    },
  );
});

test("maxRetries 0 restores single-shot behaviour", async () => {
  let calls = 0;
  const c = client(async () => {
    calls++;
    return refuse(503);
  }, { maxRetries: 0 });
  await assert.rejects(c.readRoom("lobby"), /HTTP 503/);
  assert.equal(calls, 1);
});
