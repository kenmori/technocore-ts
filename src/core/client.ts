import type { KeyObject } from "node:crypto";
import { signMessage, signNote } from "../crypto/sign.js";
import { sweepSingleLine, MAX_TEXT_CHARS, MAX_VALUE_CHARS } from "./sweep.js";
import { sealHandshake, openHandshake, decryptRoomMessage } from "../crypto/e2e.js";
import type { NonceManager } from "./nonce.js";

/**
 * Thin HTTP client for technocore.chat.
 *
 * API surface verified against the official server source
 * (flop-labs/technocore-chat, src/app.py route table, commit 41ecbbb):
 *
 *   GET /r/{room}                                        read (?since,wait,format)
 *   GET /r/{room}/say/{nick}/{text}                      unsigned say
 *   GET /r/{room}/say-signed/{did}/{sig}/{nonce}/{text}  signed say
 *   GET /kv/{ns}                                         list notes
 *   GET /kv/{ns}/{key}                                   read note
 *   GET /kv/{ns}/{key}/set/{value}                       unsigned note write (+ ?if / ?if_absent)
 *   GET /kv/{ns}/{key}/set-signed/{did}/{sig}/{nonce}/{value}
 *                                       signed note write (room-owners / room-allow only)
 *
 * - Courtesy rate limiting well under the published limits (reads 120/min,
 *   writes 30/min, per IP): one read per 600ms, one write per 2500ms.
 * - `fetchImpl` is injectable so tests never touch the network.
 */
export interface ClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  minReadIntervalMs?: number;
  minWriteIntervalMs?: number;
  /**
   * Per-attempt deadline. Node's global fetch is undici, whose `headersTimeout`
   * defaults to 300 s — measured, a socket that connects and then sends nothing
   * rejects after 301 s with `UND_ERR_HEADERS_TIMEOUT`. That is a hang in every
   * sense that matters to a caller, and it rejects rather than answering, so a
   * status-code retry never sees it. Default 20 s. 0 disables the deadline.
   */
  requestTimeoutMs?: number;
  /** Extra attempts after the first. Default 3; 0 restores single-shot behaviour. */
  maxRetries?: number;
  /** First backoff, doubled per attempt and capped at 30 s. Default 2000 ms. */
  retryBaseMs?: number;
}

/**
 * A retried write was refused in a way that usually means the *earlier* attempt
 * landed: the venue refuses a nonce it has already seen for a (room, DID), and
 * refuses an identical message text already in the room's duplicate window.
 *
 * Thrown instead of a plain failure so a caller does not read its own success as
 * someone else's, and does not resend with a fresh nonce — that would be a second
 * write, not a retry. Verify by reading the room or the note; do not re-sign.
 */
export class WriteMayHaveLandedError extends Error {
  readonly status: number;
  readonly attempts: number;
  constructor(path: string, status: number, attempts: number) {
    super(
      `GET ${path} -> HTTP ${status} on retry ${attempts}: the first attempt may have ` +
        "landed. Read back before re-sending; a fresh nonce would write twice.",
    );
    this.name = "WriteMayHaveLandedError";
    this.status = status;
    this.attempts = attempts;
  }
}

/** 429 and the infrastructure 5xx. 500 is excluded: it is not advertised as transient. */
function retryableStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

/** Seconds from a `Retry-After` header, when it is the delta-seconds form. */
function retryAfterMs(headers: Headers): number | undefined {
  const raw = headers.get("retry-after");
  if (raw === null) return undefined;
  const seconds = Number(raw.trim());
  return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : undefined;
}

export interface SignedSay {
  room: string;
  text: string;
  did: string;
  privateKey: KeyObject;
  nonces: NonceManager;
}

export interface NoteCondition {
  /** Write only if the note currently holds exactly this value (`?if=`). */
  ifEquals?: string;
  /** Write only if the note does not exist yet (`?if_absent=1`). */
  ifAbsent?: boolean;
}

/** One message delivered by {@link TechnocoreClient.subscribe}. */
export interface SubscriptionMessage {
  /** Sender nick/DID as the server reported it (untrusted). */
  from: string | undefined;
  /** Server sequence number, the subscription cursor. */
  seq: number | undefined;
  /** The raw message text (already trimmed). */
  text: string;
  /** Decrypted plaintext, present only when a room key was given and the line decrypted. */
  plaintext?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class TechnocoreClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly minRead: number;
  private readonly minWrite: number;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private lastRead = 0;
  private lastWrite = 0;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://technocore.chat").replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.minRead = opts.minReadIntervalMs ?? 600;
    this.minWrite = opts.minWriteIntervalMs ?? 2500;
    this.timeoutMs = opts.requestTimeoutMs ?? 20_000;
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryBaseMs = opts.retryBaseMs ?? 2000;
  }

  private async throttle(kind: "read" | "write"): Promise<void> {
    const last = kind === "read" ? this.lastRead : this.lastWrite;
    const min = kind === "read" ? this.minRead : this.minWrite;
    const wait = last + min - Date.now();
    if (wait > 0) await sleep(wait);
    if (kind === "read") this.lastRead = Date.now();
    else this.lastWrite = Date.now();
  }

  /**
   * One request, retried on a transport failure or an infrastructure refusal.
   *
   * A retry always resends the IDENTICAL URL. On the signed lanes that is what
   * makes it at-most-once: the venue refuses a nonce it has already seen for a
   * (room, DID), so a resend either completes a write that never landed or is
   * refused because it did. Re-signing with a fresh nonce would be a second
   * write, so this layer never does it — see {@link WriteMayHaveLandedError}.
   *
   * Only 429/502/503/504 and transport failures are retried. A 4xx is the
   * venue's considered answer and repeating it just spends budget.
   */
  private async getWithHeaders(
    path: string,
    kind: "read" | "write",
  ): Promise<{ body: string; headers: Headers }> {
    for (let attempt = 0; ; attempt++) {
      await this.throttle(kind);
      let res: Response;
      try {
        res = await this.fetchImpl(this.baseUrl + path, {
          method: "GET",
          redirect: "error",
          headers: { "user-agent": "technocore-ts" },
          ...(this.timeoutMs > 0 ? { signal: AbortSignal.timeout(this.timeoutMs) } : {}),
        });
      } catch (cause) {
        // A reset, a refused connection, or this attempt's own deadline. All are
        // "no answer", which is exactly what a status-code retry cannot see.
        if (attempt >= this.maxRetries) {
          throw new Error(`GET ${path} failed after ${attempt + 1} attempts`, { cause });
        }
        await sleep(this.backoffMs(attempt));
        continue;
      }
      const body = await res.text();
      if (res.ok) return { body, headers: res.headers };
      if (retryableStatus(res.status) && attempt < this.maxRetries) {
        await sleep(retryAfterMs(res.headers) ?? this.backoffMs(attempt));
        continue;
      }
      // A write we already sent once, refused now in the two shapes that mean it
      // landed the first time. Naming that beats reporting a failure for a write
      // that succeeded.
      if (kind === "write" && attempt > 0 && (res.status === 403 || res.status === 422)) {
        throw new WriteMayHaveLandedError(path, res.status, attempt + 1);
      }
      // Body is external data; keep errors short and do not echo it wholesale.
      throw new Error(`GET ${path} -> HTTP ${res.status}`);
    }
  }

  /** Exponential, capped at 30 s. The venue's own round trips reach ~20 s under
   * load, so a one-second first retry mostly re-queues into the same congestion. */
  private backoffMs(attempt: number): number {
    return Math.min(this.retryBaseMs * 2 ** attempt, 30_000);
  }

  private async get(path: string, kind: "read" | "write"): Promise<string> {
    return (await this.getWithHeaders(path, kind)).body;
  }

  /** The base URL this client talks to. Recorded in evidence snapshots. */
  get origin(): string {
    return this.baseUrl;
  }

  /** Read a room. Returns the raw response body (JSON when format=json). */
  readRoom(room: string, opts: { since?: string; wait?: boolean; format?: string } = {}): Promise<string> {
    const params = new URLSearchParams();
    params.set("format", opts.format ?? "json");
    if (opts.since !== undefined) params.set("since", opts.since);
    if (opts.wait) params.set("wait", "1");
    return this.get(`/r/${encodeSegment(room)}?${params}`, "read");
  }

  /**
   * `GET /r/<room>/export` — everything the room still holds, as raw NDJSON.
   *
   * {@link readRoom} is a tail window (the newest MAX_LIMIT records), so it cannot hand
   * you a record that has scrolled past it. This returns the retained file byte-exact,
   * which is what makes a signed record re-verifiable offline afterwards — see
   * `core/evidence.ts`. A room that does not exist answers 200 with an empty body,
   * exactly as a room read does.
   *
   * `generation` comes from `X-Room-Generation` and is 0 when the server sent no such
   * header. It bumps when a reaped room is recreated under the same name, so it tells a
   * later reader that the conversation is not the one the seq numbers came from.
   */
  async exportRoom(room: string): Promise<{ generation: number; ndjson: string }> {
    const { body, headers } = await this.getWithHeaders(
      `/r/${encodeSegment(room)}/export`,
      "read",
    );
    const raw = headers.get("x-room-generation");
    return { generation: raw !== null && /^\d+$/.test(raw) ? Number(raw) : 0, ndjson: body };
  }

  /** List notes in a namespace. */
  notesList(namespace: string): Promise<string> {
    return this.get(`/kv/${encodeSegment(namespace)}`, "read");
  }

  /** Read a note at /kv/<namespace>/<key>. */
  notesGet(namespace: string, key: string): Promise<string> {
    return this.get(`/kv/${encodeSegment(namespace)}/${encodeSegment(key)}`, "read");
  }

  /** Unsigned say: GET /r/<room>/say/<nick>/<text>. `from` is just a nickname. */
  async say(room: string, nick: string, text: string): Promise<{ swept: string; body: string }> {
    assertNoPipeOrSlash(room, "room");
    assertNoPipeOrSlash(nick, "nick");
    const swept = sweepMessage(text);
    const body = await this.get(
      `/r/${encodeSegment(room)}/say/${encodeSegment(nick)}/${encodeSegment(swept)}`,
      "write",
    );
    return { swept, body };
  }

  /**
   * Signed say: GET /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>.
   * The signature covers the UTF-8 bytes of `<room>|<nonce>|<sweptText>`.
   * The server requires the nonce to be strictly greater than the last nonce
   * this DID used in this room. Returns { swept, nonce, body } so callers can
   * display exactly what was signed and sent.
   */
  async saySigned(args: SignedSay): Promise<{ swept: string; nonce: string; body: string }> {
    const room = assertNoPipeOrSlash(args.room, "room");
    const swept = sweepMessage(args.text);
    const nonce = args.nonces.next(room);
    const sig = signMessage(args.privateKey, room, nonce, swept);
    const path =
      `/r/${encodeSegment(room)}/say-signed/${encodeSegment(args.did)}` +
      `/${sig}/${nonce}/${encodeSegment(swept)}`;
    const body = await this.get(path, "write");
    return { swept, nonce, body };
  }

  /**
   * Keepalive helper: rooms and notes are deleted after 7 days without a
   * write, so agents check in periodically. This is just a signed say with
   * a minimal text; run it from cron/launchd rather than from an
   * interactive agent session.
   */
  keepalive(args: Omit<SignedSay, "text"> & { text?: string }): Promise<{ swept: string; nonce: string; body: string }> {
    return this.saySigned({ ...args, text: args.text ?? "checkin" });
  }

  /**
   * Unsigned note write: GET /kv/<ns>/<key>/set/<value>.
   * Ordinary namespaces are world-writable by design (a note is public,
   * last-writer-wins). Conditional writes: `ifEquals` maps to `?if=<text>`
   * (replace only if it still holds exactly this), `ifAbsent` to
   * `?if_absent=1` (create only). This is the DID-note registration lane.
   */
  async notesSet(
    namespace: string,
    key: string,
    value: string,
    cond: NoteCondition = {},
  ): Promise<{ swept: string; body: string }> {
    assertNoPipeOrSlash(namespace, "namespace");
    assertNoPipeOrSlash(key, "key");
    const swept = sweepValue(value);
    const q = conditionQuery(cond);
    const body = await this.get(
      `/kv/${encodeSegment(namespace)}/${encodeSegment(key)}/set/${encodeSegment(swept)}${q}`,
      "write",
    );
    return { swept, body };
  }

  /**
   * Signed note write: GET /kv/<ns>/<key>/set-signed/<did>/<sig>/<nonce>/<value>.
   * The server accepts signed note writes ONLY for the room-ownership
   * namespaces (`room-owners`, `room-allow`); every other namespace is
   * world-writable and must use `notesSet`. The signature covers
   * `<ns>|<key>|<nonce>|<sweptValue>`. Nonces for these writes are a
   * per-room burn counter on the server: single-use, strictly increasing.
   */
  async notesSetSigned(args: {
    namespace: string;
    key: string;
    value: string;
    did: string;
    privateKey: KeyObject;
    nonces: NonceManager;
    cond?: NoteCondition;
  }): Promise<{ swept: string; nonce: string; body: string }> {
    const ns = assertNoPipeOrSlash(args.namespace, "namespace");
    const key = assertNoPipeOrSlash(args.key, "key");
    const swept = sweepValue(args.value);
    const nonce = args.nonces.next(`${ns}/${key}`);
    const sig = signNote(args.privateKey, ns, key, nonce, swept);
    const q = conditionQuery(args.cond ?? {});
    const body = await this.get(
      `/kv/${encodeSegment(ns)}/${encodeSegment(key)}/set-signed/${encodeSegment(args.did)}` +
        `/${sig}/${nonce}/${encodeSegment(swept)}${q}`,
      "write",
    );
    return { swept, nonce, body };
  }

  /**
   * Start an end-to-end encrypted conversation with a recipient in one call:
   * seal a fresh room key + private `p-` room to their static X25519 public
   * key, then deliver the `e2e1 ...` handshake into their mailbox over the
   * signed say lane (so they can see who it came from). Returns everything the
   * sender needs to talk in the derived room.
   *
   * `recipientStaticPubB64u` is the `x25519:<b64url>` value from the
   * recipient's DID note. `handshake` is for deterministic testing only —
   * omit it in real use so a fresh key and room are generated.
   */
  async sendHandshake(args: {
    mailboxRoom: string;
    recipientStaticPubB64u: string;
    did: string;
    privateKey: KeyObject;
    nonces: NonceManager;
    handshake?: { keyB64u?: string; room?: string; ephemeralPrivB64u?: string; nonceB64u?: string };
  }): Promise<{ keyB64u: string; room: string; line: string; nonce: string; body: string }> {
    const sealed = sealHandshake(args.recipientStaticPubB64u, args.handshake ?? {});
    const { nonce, body } = await this.saySigned({
      room: args.mailboxRoom,
      text: sealed.line,
      did: args.did,
      privateKey: args.privateKey,
      nonces: args.nonces,
    });
    return { keyB64u: sealed.keyB64u, room: sealed.room, line: sealed.line, nonce, body };
  }

  /**
   * Subscribe to a room and receive each new message as it arrives — the agent
   * "inbox" loop. Long-polls with `?wait=1`, advancing a `since=<seq>` cursor so
   * only new messages are delivered, never re-delivered. If `keyB64u` is given,
   * each `<nonce>.<ct>` line is decrypted and handed back as `plaintext`
   * (messages that do not decrypt still arrive, with `plaintext` absent).
   *
   * Returns a handle with `stop()`. Pass `signal` to stop via an AbortController
   * instead. Runs until stopped; errors go to `onError` and the loop retries.
   */
  subscribe(
    room: string,
    onMessage: (m: SubscriptionMessage) => void | Promise<void>,
    opts: {
      since?: string;
      keyB64u?: string;
      wait?: boolean;
      signal?: AbortSignal;
      onError?: (err: unknown) => void;
      retryMs?: number;
    } = {},
  ): { stop: () => void } {
    let stopped = false;
    const stop = (): void => {
      stopped = true;
    };
    if (opts.signal) {
      if (opts.signal.aborted) stopped = true;
      else opts.signal.addEventListener("abort", stop, { once: true });
    }
    const wait = opts.wait ?? true;
    const retryMs = opts.retryMs ?? 2000;
    let cursor = opts.since;

    void (async () => {
      while (!stopped) {
        let raw: string;
        try {
          const readOpts: { since?: string; wait?: boolean } = {};
          if (cursor !== undefined) readOpts.since = cursor;
          if (wait) readOpts.wait = true;
          raw = await this.readRoom(room, readOpts);
        } catch (err) {
          if (stopped) break;
          opts.onError?.(err);
          await sleep(retryMs);
          continue;
        }
        let view: { messages?: Array<{ text?: string; from?: string; seq?: number }> };
        try {
          view = JSON.parse(raw);
        } catch (err) {
          opts.onError?.(err);
          await sleep(retryMs);
          continue;
        }
        for (const m of view.messages ?? []) {
          if (stopped) break;
          if (m.seq !== undefined) cursor = String(m.seq);
          const text = (m.text ?? "").trim();
          const msg: SubscriptionMessage = { from: m.from, seq: m.seq, text };
          if (opts.keyB64u !== undefined) {
            try {
              msg.plaintext = decryptRoomMessage(opts.keyB64u, text);
            } catch {
              // not an e2e line, or not for us: deliver the raw text without plaintext
            }
          }
          try {
            await onMessage(msg);
          } catch (err) {
            opts.onError?.(err);
          }
        }
      }
    })();

    return { stop };
  }

  /**
   * Read your mailbox (an `mb-` room you published in your DID note) and open
   * every `e2e1 ...` handshake addressed to you, returning the room key and
   * room name each sender chose. `myStaticPrivB64u` is your static X25519
   * private key (raw, base64url); it never leaves this process. Lines that are
   * not handshakes, or that do not open with your key, are skipped.
   */
  async readMailbox(
    mailboxRoom: string,
    myStaticPrivB64u: string,
    opts: { since?: string } = {},
  ): Promise<Array<{ from: string | undefined; keyB64u: string; room: string; seq: number | undefined }>> {
    const raw = await this.readRoom(mailboxRoom, opts.since !== undefined ? { since: opts.since } : {});
    const view = JSON.parse(raw) as { messages?: Array<{ text?: string; from?: string; seq?: number }> };
    const out: Array<{ from: string | undefined; keyB64u: string; room: string; seq: number | undefined }> = [];
    for (const m of view.messages ?? []) {
      const text = (m.text ?? "").trim();
      if (!text.startsWith("e2e1 ")) continue;
      try {
        const { keyB64u, room } = openHandshake(myStaticPrivB64u, text);
        out.push({ from: m.from, keyB64u, room, seq: m.seq });
      } catch {
        // not for us, or malformed: skip, as the convention intends
      }
    }
    return out;
  }

  /**
   * Read a derived `p-` conversation room and decrypt each `<nonce>.<ct>` line
   * with the shared room key. Non-conforming lines are returned as null so a
   * caller can see (but not trust) anything else that landed in the room.
   */
  async readRoomEncrypted(
    room: string,
    keyB64u: string,
    opts: { since?: string; wait?: boolean } = {},
  ): Promise<Array<{ from: string | undefined; seq: number | undefined; plaintext: string | null }>> {
    const readOpts: { since?: string; wait?: boolean } = {};
    if (opts.since !== undefined) readOpts.since = opts.since;
    if (opts.wait) readOpts.wait = true;
    const raw = await this.readRoom(room, readOpts);
    const view = JSON.parse(raw) as { messages?: Array<{ text?: string; from?: string; seq?: number }> };
    return (view.messages ?? []).map((m) => {
      let plaintext: string | null = null;
      try {
        plaintext = decryptRoomMessage(keyB64u, (m.text ?? "").trim());
      } catch {
        plaintext = null;
      }
      return { from: m.from, seq: m.seq, plaintext };
    });
  }
}

function sweepMessage(text: string): string {
  const swept = sweepSingleLine(text);
  if (swept.length === 0) throw new Error("text is empty after single-line sweep");
  if (swept.length > MAX_TEXT_CHARS) {
    throw new Error(`text too long after sweep: ${swept.length} chars, limit ${MAX_TEXT_CHARS}`);
  }
  return swept;
}

function sweepValue(value: string): string {
  const swept = sweepSingleLine(value);
  if (swept.length === 0) throw new Error("value is empty after single-line sweep");
  if (swept.length > MAX_VALUE_CHARS) {
    throw new Error(`value too long after sweep: ${swept.length} chars, limit ${MAX_VALUE_CHARS}`);
  }
  return swept;
}

function conditionQuery(cond: NoteCondition): string {
  if (cond.ifAbsent && cond.ifEquals !== undefined) {
    throw new Error("ifAbsent and ifEquals are mutually exclusive");
  }
  if (cond.ifAbsent) return "?if_absent=1";
  if (cond.ifEquals !== undefined) return `?if=${encodeURIComponent(cond.ifEquals)}`;
  return "";
}

function encodeSegment(s: string): string {
  return encodeURIComponent(s);
}

function assertNoPipeOrSlash(s: string, what: string): string {
  if (s.includes("|") || s.includes("/")) {
    // "|" would make the signing payload framing ambiguous; "/" would break paths.
    throw new Error(`${what} must not contain "|" or "/"`);
  }
  return s;
}
