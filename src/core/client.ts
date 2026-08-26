import type { KeyObject } from "node:crypto";
import { signMessage } from "../crypto/sign.js";
import { sweepSingleLine } from "./sweep.js";
import type { NonceManager } from "./nonce.js";

/**
 * Thin HTTP client for technocore.chat.
 *
 * - GET-only API, per the site's design.
 * - Courtesy rate limiting well under the published limits
 *   (reads 120/min, writes 30/min, per IP): one read per 600ms,
 *   one write per 2500ms, enforced in-process.
 * - `fetchImpl` is injectable so tests never touch the network.
 */
export interface ClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  minReadIntervalMs?: number;
  minWriteIntervalMs?: number;
}

export interface SignedSay {
  room: string;
  text: string;
  did: string;
  privateKey: KeyObject;
  nonces: NonceManager;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class TechnocoreClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly minRead: number;
  private readonly minWrite: number;
  private lastRead = 0;
  private lastWrite = 0;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://technocore.chat").replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.minRead = opts.minReadIntervalMs ?? 600;
    this.minWrite = opts.minWriteIntervalMs ?? 2500;
  }

  private async throttle(kind: "read" | "write"): Promise<void> {
    const last = kind === "read" ? this.lastRead : this.lastWrite;
    const min = kind === "read" ? this.minRead : this.minWrite;
    const wait = last + min - Date.now();
    if (wait > 0) await sleep(wait);
    if (kind === "read") this.lastRead = Date.now();
    else this.lastWrite = Date.now();
  }

  private async get(path: string, kind: "read" | "write"): Promise<string> {
    await this.throttle(kind);
    const res = await this.fetchImpl(this.baseUrl + path, {
      method: "GET",
      redirect: "error",
      headers: { "user-agent": "technocore-ts" },
    });
    const body = await res.text();
    if (!res.ok) {
      // Body is external data; keep errors short and do not echo it wholesale.
      throw new Error(`GET ${path} -> HTTP ${res.status}`);
    }
    return body;
  }

  /** Read a room. Returns the raw response body (JSON when format=json). */
  readRoom(room: string, opts: { since?: string; wait?: boolean; format?: string } = {}): Promise<string> {
    const params = new URLSearchParams();
    params.set("format", opts.format ?? "json");
    if (opts.since !== undefined) params.set("since", opts.since);
    if (opts.wait) params.set("wait", "1");
    return this.get(`/r/${encodeSegment(room)}?${params}`, "read");
  }

  /** Read a note at /kv/<namespace>/<key>. */
  notesGet(namespace: string, key: string): Promise<string> {
    return this.get(`/kv/${encodeSegment(namespace)}/${encodeSegment(key)}`, "read");
  }

  /**
   * Signed message: GET /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>.
   * The signature covers the UTF-8 bytes of `<room>|<nonce>|<sweptText>`.
   * Returns { swept, nonce, body } so callers can display exactly what was
   * signed and sent.
   */
  async saySigned(args: SignedSay): Promise<{ swept: string; nonce: string; body: string }> {
    const room = assertNoPipe(args.room, "room");
    const swept = sweepSingleLine(args.text);
    if (swept.length === 0) throw new Error("text is empty after single-line sweep");
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
   * !! SPEC-PENDING !!
   * Note writes: the exact write path/params for /kv are defined by the
   * official spec (llms.txt / patterns.md) and must be confirmed against it.
   * This method is deliberately not implemented until then — guessing a
   * write API against a live service is worse than failing loudly.
   */
  notesSet(): never {
    throw new Error(
      "notesSet is not implemented yet: the /kv write API must be confirmed against " +
        "https://technocore.chat/llms.txt before this client will write notes (SPEC-PENDING).",
    );
  }
}

function encodeSegment(s: string): string {
  return encodeURIComponent(s);
}

function assertNoPipe(s: string, what: string): string {
  if (s.includes("|") || s.includes("/")) {
    // "|" would make the signing payload framing ambiguous; "/" would break paths.
    throw new Error(`${what} must not contain "|" or "/"`);
  }
  return s;
}
