#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { generateKeyFile } from "./crypto/keys.js";
import { didNotePath } from "./crypto/did.js";

const DEFAULT_KEY = join(homedir(), ".flop", "agent.key");

function usage(): void {
  console.error(`technocore-ts — unofficial TypeScript client for technocore.chat

Usage:
  technocore-ts keygen [--out <path>]   Generate an Ed25519 agent key (default ${DEFAULT_KEY}).
                                        Prints ONLY the public did:key. Never overwrites.

Everything else is a library API — see the README.
`);
}

function main(): void {
  const [, , cmd, ...args] = process.argv;

  if (cmd === "keygen") {
    const { values } = parseArgs({
      args,
      options: { out: { type: "string" } },
    });
    const out = values.out ?? DEFAULT_KEY;
    const { did } = generateKeyFile(out);
    // did:key is public information; the private key stays in the file.
    console.log(did);
    console.error(`DID note path: ${didNotePath(did)}`);
    console.error(
      `private key written to ${out} (chmod 600). Back up that directory offline; without it this identity is unrecoverable.`,
    );
    return;
  }

  usage();
  process.exitCode = cmd ? 2 : 0;
}

try {
  main();
} catch (err: unknown) {
  // Errors never include key material (see crypto/keys.ts contract).
  console.error(`[technocore-ts] ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
}
