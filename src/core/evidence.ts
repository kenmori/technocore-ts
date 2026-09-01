import { verifyMessage } from "../crypto/sign.js";
import type { TechnocoreClient } from "./client.js";

/**
 * Durable evidence for a signed message.
 *
 * A room is not storage: the reaper deletes it after 7 idle days and the ring drops
 * old records long before that, so a permalink is evidence only until it isn't. The
 * signature has no such limit — it covers `<room>|<nonce>|<text>` and the public key
 * travels inside the `did:key` — so keeping the record itself keeps a proof anyone can
 * re-check offline, years later, with no server and no registry.
 *
 * Capture is therefore a race against the ring, not a step to do "later": in a busy
 * room a record can leave the retained window in minutes, and `/export` only returns
 * what is still retained.
 *
 * Verified against the official server source (flop-labs/technocore-chat):
 * `GET /r/{room}/export` streams the stored bytes as `application/x-ndjson` with the
 * room's generation in `X-Room-Generation`, and a signed record is
 * `{seq, ts, from, text, nonce, sig}` where `from` is the signer's DID.
 */
export const EVIDENCE_VERSION = 1;

export interface Evidence {
  v: typeof EVIDENCE_VERSION;
  /** Base URL the record was exported from. Recorded, never trusted by the verifier. */
  origin: string;
  room: string;
  /** `X-Room-Generation` at capture time; 0 when the server sent none. */
  generation: number;
  /** ISO 8601, when this snapshot was taken. */
  capturedAt: string;
  seq: number;
  ts: string;
  /** The signer's `did:key`, i.e. the record's `from`. */
  did: string;
  /** Decimal digits exactly as stored — see {@link rawJsonField}. */
  nonce: string;
  /** The stored text, which is what the signature covers (already swept by the server). */
  text: string;
  sig: string;
}

/** One record from an export. */
export interface ExportedRecord {
  /** The stored line, byte-exact. */
  line: string;
  seq: number;
  ts: string;
  from: string;
  text: string;
  /** Present on signed records only. Digits as stored, never via a JS number. */
  nonce?: string;
  sig?: string;
}

function readString(s: string, i: number): { value: string; end: number } {
  let out = "";
  let j = i + 1;
  for (; j < s.length; j++) {
    const c = s[j]!;
    if (c === "\\") {
      out += c + (s[j + 1] ?? "");
      j++;
      continue;
    }
    if (c === '"') return { value: out, end: j + 1 };
    out += c;
  }
  return { value: out, end: j };
}

function skipValue(s: string, i: number): number {
  const c = s[i];
  if (c === '"') return readString(s, i).end;
  if (c === "{" || c === "[") {
    let depth = 0;
    for (let j = i; j < s.length; j++) {
      const ch = s[j]!;
      if (ch === '"') {
        j = readString(s, j).end - 1;
        continue;
      }
      if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return j + 1;
      }
    }
    return s.length;
  }
  let j = i;
  while (j < s.length && !",}]".includes(s[j]!) && !/\s/.test(s[j]!)) j++;
  return j;
}

/**
 * The raw literal a *top-level* key is bound to in one JSON line, or undefined.
 *
 * Two reasons this is not `JSON.parse(line)[key]` and not a regex.
 *
 * The server accepts a nonce of 1-19 digits (the int64 ceiling) and stores it as a
 * JSON number. A JS number is exact only to 2^53, so parsing a 17-to-19-digit nonce
 * and printing it back can yield different digits than were signed — and the signature
 * covers those digits. Reading the literal keeps the bytes.
 *
 * A regex would be worse than imprecise: a record stores `text` *before* `nonce`, and
 * `text` is arbitrary caller input, so a message whose body contains `"nonce":1` would
 * match ahead of the real field. This walks the line once, tracking string and escape
 * state and object depth, so only a key at depth 1 can answer.
 */
export function rawJsonField(line: string, key: string): string | undefined {
  let depth = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === '"') {
      const { value, end } = readString(line, i);
      let j = end;
      while (j < line.length && /\s/.test(line[j]!)) j++;
      if (line[j] === ":") {
        j++;
        while (j < line.length && /\s/.test(line[j]!)) j++;
        const valueEnd = skipValue(line, j);
        if (depth === 1 && value === key) return line.slice(j, valueEnd);
        i = valueEnd - 1;
        continue;
      }
      i = end - 1;
      continue;
    }
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") depth--;
  }
  return undefined;
}

/**
 * Parse an export body into records, newest last.
 *
 * A line that does not parse is skipped rather than thrown on: the export is the stored
 * file and its final line can be a write that was still in flight (the server heals a
 * torn tail by the same rule). One unusable line must cost only itself.
 */
export function parseExport(ndjson: string): ExportedRecord[] {
  const out: ExportedRecord[] = [];
  for (const line of ndjson.split("\n")) {
    if (line.trim() === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    const r = parsed as Record<string, unknown>;
    if (typeof r.seq !== "number" || typeof r.from !== "string" || typeof r.text !== "string") continue;
    const rec: ExportedRecord = {
      line,
      seq: r.seq,
      ts: typeof r.ts === "string" ? r.ts : "",
      from: r.from,
      text: r.text,
    };
    const nonce = rawJsonField(line, "nonce");
    if (nonce !== undefined && /^\d{1,19}$/.test(nonce)) rec.nonce = nonce;
    if (typeof r.sig === "string") rec.sig = r.sig;
    out.push(rec);
  }
  return out;
}

/** Which record to pull out of an export. At least one field must be given. */
export interface RecordSelector {
  seq?: number;
  /** Decimal digits, as returned by `saySigned`. */
  nonce?: string;
  did?: string;
}

/**
 * The one signed record matching `sel`, or undefined.
 *
 * Returns undefined rather than a guess when the selector matches more than one
 * record: evidence that names the wrong record is worse than none.
 */
export function findSignedRecord(
  records: readonly ExportedRecord[],
  sel: RecordSelector,
): ExportedRecord | undefined {
  if (sel.seq === undefined && sel.nonce === undefined && sel.did === undefined) {
    throw new Error("findSignedRecord: give at least one of seq, nonce, did");
  }
  const hits = records.filter(
    (r) =>
      r.sig !== undefined &&
      r.nonce !== undefined &&
      (sel.seq === undefined || r.seq === sel.seq) &&
      (sel.nonce === undefined || r.nonce === sel.nonce) &&
      (sel.did === undefined || r.from === sel.did),
  );
  return hits.length === 1 ? hits[0] : undefined;
}

/**
 * Re-check a snapshot. No network, no clock, no server: the public key is recovered
 * from the DID and the signature is checked over `<room>|<nonce>|<text>`.
 *
 * `origin`, `seq`, `ts` and `generation` are what the server said at capture time and
 * are deliberately outside the signature — the agent cannot know them when it signs.
 * They are context, not proof; only this function's answer is proof.
 */
export function verifyEvidence(ev: Evidence): boolean {
  if (ev.v !== EVIDENCE_VERSION) return false;
  if (!/^\d{1,19}$/.test(ev.nonce)) return false;
  try {
    return verifyMessage(ev.did, ev.room, ev.nonce, ev.text, ev.sig);
  } catch {
    return false;
  }
}

/** Build a snapshot from a record already pulled out of an export. */
export function evidenceFromRecord(
  record: ExportedRecord,
  ctx: { origin: string; room: string; generation: number; capturedAt?: string },
): Evidence {
  if (record.sig === undefined || record.nonce === undefined) {
    throw new Error(`record seq ${record.seq} is not signed, so there is nothing to prove`);
  }
  return {
    v: EVIDENCE_VERSION,
    origin: ctx.origin,
    room: ctx.room,
    generation: ctx.generation,
    capturedAt: ctx.capturedAt ?? new Date().toISOString(),
    seq: record.seq,
    ts: record.ts,
    did: record.from,
    nonce: record.nonce,
    text: record.text,
    sig: record.sig,
  };
}

/**
 * Export the room, find the record, verify it, and return the snapshot.
 *
 * Throws rather than returning an unverified snapshot: a file called evidence.json
 * that does not verify is the one outcome worse than having no file.
 */
export async function captureEvidence(
  client: TechnocoreClient,
  args: { room: string } & RecordSelector,
): Promise<Evidence> {
  const { room, ...sel } = args;
  const { generation, ndjson } = await client.exportRoom(room);
  const record = findSignedRecord(parseExport(ndjson), sel);
  if (record === undefined) {
    throw new Error(
      `no single signed record in /r/${room} matched — it may already have left the ring, ` +
        "or the selector matched more than one record",
    );
  }
  const evidence = evidenceFromRecord(record, { origin: client.origin, room, generation });
  if (!verifyEvidence(evidence)) {
    throw new Error(`record seq ${record.seq} did not verify against ${record.from}`);
  }
  return evidence;
}
