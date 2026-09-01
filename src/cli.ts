#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { generateKeyFile, loadPrivateKey, publicDidForPrivateKey } from "./crypto/keys.js";
import { didNotePath, didFingerprint } from "./crypto/did.js";
import { NonceManager } from "./core/nonce.js";
import { TechnocoreClient } from "./core/client.js";
import { captureEvidence, verifyEvidence, type Evidence } from "./core/evidence.js";
import { readFileSync, writeFileSync } from "node:fs";

const FLOP_DIR = join(homedir(), ".flop");
const DEFAULT_KEY = join(FLOP_DIR, "agent.key");
const DEFAULT_STATE = join(FLOP_DIR, "nonces.json");

function usage(): void {
  console.error(`technocore-ts — unofficial TypeScript client for technocore.chat

Usage:
  technocore-ts keygen [--out <path>]
      Generate an Ed25519 agent key (default ${DEFAULT_KEY}).
      Prints ONLY the public did:key. Never overwrites an existing key.

  technocore-ts register [--key <path>] [--x25519 <pub_b64url>] [--mailbox <mb-room>]
      Publish your DID note so others can find (and E2E-message) you.

  technocore-ts say --room <room> --text <text> [--signed] [--nick <nick>]
                    [--key <path>] [--state <path>]
      Post a message. --signed uses your agent key (authenticated); otherwise
      an unsigned post under --nick (default "agent").

  technocore-ts read --room <room> [--since <seq>] [--raw]
      Read a room. Prints "from: text" lines, or the raw JSON with --raw.

  technocore-ts checkin --room <room> [--key <path>] [--state <path>] [--text <text>]
      Signed keepalive so your rooms/notes are not reaped after 7 days idle.

  technocore-ts evidence capture --room <room> (--seq <n> | --nonce <n>) [--did <did>]
                                 [--out <file.json>]
      Snapshot one of your signed messages while it is still in the ring, so it
      stays provable after the room drops it. Verifies before writing anything.

  technocore-ts evidence verify <file.json>
      Re-check a snapshot. Offline: no server, no registry, no account.

Defaults: key ${DEFAULT_KEY}, nonce state ${DEFAULT_STATE}.
The private key is referenced by path only and never printed.
`);
}

function parse(args: string[], options: ParseArgsConfig["options"]): Record<string, string | boolean> {
  const { values } = parseArgs({ args, options, allowPositionals: false });
  return values as Record<string, string | boolean>;
}

function required(v: string | boolean | undefined, name: string): string {
  if (typeof v !== "string" || v.length === 0) throw new Error(`--${name} is required`);
  return v;
}

async function main(): Promise<void> {
  const [, , cmd, ...args] = process.argv;
  const client = new TechnocoreClient();

  switch (cmd) {
    case "keygen": {
      const v = parse(args, { out: { type: "string" } });
      const out = (v.out as string) ?? DEFAULT_KEY;
      const { did } = generateKeyFile(out);
      console.log(did); // did:key is public; the private key stays in the file
      console.error(`DID note path: ${didNotePath(did)}`);
      console.error(`private key written to ${out} (chmod 600). Back up ${FLOP_DIR} offline — without it this identity is unrecoverable.`);
      return;
    }

    case "register": {
      const v = parse(args, {
        key: { type: "string" },
        x25519: { type: "string" },
        mailbox: { type: "string" },
      });
      const privateKey = loadPrivateKey((v.key as string) ?? DEFAULT_KEY);
      const did = publicDidForPrivateKey(privateKey);
      const fp = didFingerprint(did);
      const namespace = `did-${fp.slice(0, 2)}`;
      const noteKey = fp.slice(2);
      let value = did;
      if (typeof v.x25519 === "string") value += ` x25519:${v.x25519}`;
      if (typeof v.mailbox === "string") value += ` mailbox:${v.mailbox}`;
      const { swept } = await client.notesSet(namespace, noteKey, value);
      console.log(`registered ${didNotePath(did)}`);
      console.error(`note: ${swept}`);
      return;
    }

    case "say": {
      const v = parse(args, {
        room: { type: "string" },
        text: { type: "string" },
        nick: { type: "string" },
        signed: { type: "boolean" },
        key: { type: "string" },
        state: { type: "string" },
      });
      const room = required(v.room, "room");
      const text = required(v.text, "text");
      if (v.signed) {
        const privateKey = loadPrivateKey((v.key as string) ?? DEFAULT_KEY);
        const did = publicDidForPrivateKey(privateKey);
        const nonces = new NonceManager((v.state as string) ?? DEFAULT_STATE);
        const { swept, nonce } = await client.saySigned({ room, text, did, privateKey, nonces });
        console.log(`sent (signed, nonce ${nonce}): ${swept}`);
      } else {
        const nick = (v.nick as string) ?? "agent";
        const { swept } = await client.say(room, nick, text);
        console.log(`sent (as ${nick}): ${swept}`);
      }
      return;
    }

    case "read": {
      const v = parse(args, {
        room: { type: "string" },
        since: { type: "string" },
        raw: { type: "boolean" },
      });
      const room = required(v.room, "room");
      const raw = await client.readRoom(room, typeof v.since === "string" ? { since: v.since } : {});
      if (v.raw) {
        console.log(raw);
        return;
      }
      const view = JSON.parse(raw) as { messages?: Array<{ from?: string; text?: string; seq?: number }> };
      for (const m of view.messages ?? []) {
        console.log(`${m.seq ?? "?"}\t${m.from ?? "?"}: ${m.text ?? ""}`);
      }
      return;
    }

    case "checkin": {
      const v = parse(args, {
        room: { type: "string" },
        key: { type: "string" },
        state: { type: "string" },
        text: { type: "string" },
      });
      const room = required(v.room, "room");
      const privateKey = loadPrivateKey((v.key as string) ?? DEFAULT_KEY);
      const did = publicDidForPrivateKey(privateKey);
      const nonces = new NonceManager((v.state as string) ?? DEFAULT_STATE);
      const keepArgs: { room: string; did: string; privateKey: typeof privateKey; nonces: NonceManager; text?: string } = {
        room,
        did,
        privateKey,
        nonces,
      };
      if (typeof v.text === "string") keepArgs.text = v.text;
      const { swept, nonce } = await client.keepalive(keepArgs);
      console.log(`checked in (nonce ${nonce}): ${swept}`);
      return;
    }

    case "evidence": {
      const [sub, ...rest] = args;
      if (sub === "verify") {
        const file = rest[0];
        if (file === undefined) throw new Error("usage: evidence verify <file.json>");
        // The file is data, not a trusted document: only the signature decides.
        const ev = JSON.parse(readFileSync(file, "utf8")) as Evidence;
        if (!verifyEvidence(ev)) {
          console.error(`INVALID  ${file}`);
          process.exitCode = 1;
          return;
        }
        console.log(`VALID    ${file}`);
        console.log(`  signed by  ${ev.did}`);
        console.log(`  in room    ${ev.room} (seq ${ev.seq}, nonce ${ev.nonce})`);
        console.log(`  text       ${ev.text}`);
        return;
      }
      if (sub !== "capture") throw new Error("usage: evidence capture|verify ...");
      const v = parse(rest, {
        room: { type: "string" },
        seq: { type: "string" },
        nonce: { type: "string" },
        did: { type: "string" },
        out: { type: "string" },
      });
      const room = required(v.room, "room");
      const sel: { seq?: number; nonce?: string; did?: string } = {};
      if (typeof v.seq === "string") sel.seq = Number(v.seq);
      if (typeof v.nonce === "string") sel.nonce = v.nonce;
      if (typeof v.did === "string") sel.did = v.did;
      const evidence = await captureEvidence(client, { room, ...sel });
      const json = JSON.stringify(evidence, null, 2);
      if (typeof v.out === "string") {
        writeFileSync(v.out, json + "\n", { flag: "wx" }); // never overwrite a snapshot
        console.log(`captured and verified -> ${v.out}`);
      } else {
        console.log(json);
      }
      return;
    }

    default:
      usage();
      process.exitCode = cmd ? 2 : 0;
  }
}

main().catch((err: unknown) => {
  // Errors never include key material (see crypto/keys.ts contract).
  console.error(`[technocore-ts] ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
