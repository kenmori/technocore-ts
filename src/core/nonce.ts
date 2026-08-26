import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Per-room monotonic nonce manager.
 *
 * Technocore requires nonces (millisecond timestamps) to be strictly
 * increasing per room. Three failure modes are handled explicitly:
 *
 * 1. Two writes in the same millisecond            -> next = last + 1
 * 2. Wall clock moving backwards                   -> next = last + 1
 * 3. Process restart (stdio MCP restarts per session) -> state is persisted
 *    to disk BEFORE a nonce is handed out, so a crash can skip nonces but
 *    never reuse one.
 *
 * Concurrent writers sharing one state file are NOT supported; run one
 * writer per key. The state file is replaced atomically via rename so a
 * reader never sees a torn file, but two writers can still race each other.
 */
export class NonceManager {
  private last = new Map<string, number>();

  constructor(
    private readonly statePath: string,
    private readonly now: () => number = Date.now,
  ) {
    try {
      const data = JSON.parse(readFileSync(statePath, "utf8")) as Record<string, number>;
      for (const [room, n] of Object.entries(data)) {
        if (typeof n === "number" && Number.isFinite(n)) this.last.set(room, n);
      }
    } catch {
      // First run or unreadable state: start fresh. Clock-based nonces make
      // a lost state file safe as long as the clock is roughly sane.
    }
  }

  /** Reserve and persist the next nonce for a room. */
  next(room: string): string {
    const prev = this.last.get(room) ?? 0;
    const nonce = Math.max(this.now(), prev + 1);
    this.last.set(room, nonce);
    this.persist();
    return String(nonce);
  }

  private persist(): void {
    const obj = Object.fromEntries(this.last);
    const tmp = `${this.statePath}.tmp`;
    mkdirSync(dirname(this.statePath), { recursive: true, mode: 0o700 });
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    renameSync(tmp, this.statePath);
  }
}
