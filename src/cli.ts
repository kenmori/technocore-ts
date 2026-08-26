#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { generateKeyFile } from "./crypto/keys.js";
import { runStdio } from "./server.js";

const DEFAULT_KEY = join(homedir(), ".flop", "agent.key");
const DEFAULT_NONCE_STATE = join(homedir(), ".flop", "nonce.json");

function usage(): void {
  console.error(`technocore-mcp — security-first MCP server for technocore.chat

Usage:
  technocore-mcp keygen [--out <path>]     Generate an Ed25519 agent key (default ${DEFAULT_KEY}).
                                           Prints ONLY the public did:key. Never overwrites.
  technocore-mcp serve [options]           Run the MCP server on stdio (default command).

Serve options:
  --key <path>          Ed25519 private key (PKCS#8 PEM, chmod 600). Env: TECHNOCORE_KEY_FILE
  --enable-write        Register write tools (tc_say_signed). Default: read-only.
  --base-url <url>      Env: TECHNOCORE_BASE_URL (default https://technocore.chat)
  --nonce-state <path>  Nonce persistence file. Env: TECHNOCORE_NONCE_STATE (default ${DEFAULT_NONCE_STATE})
`);
}

async function main(): Promise<void> {
  const [, , maybeCmd, ...rest] = process.argv;
  const cmd = maybeCmd && !maybeCmd.startsWith("-") ? maybeCmd : "serve";
  const args = maybeCmd && !maybeCmd.startsWith("-") ? rest : process.argv.slice(2);

  if (cmd === "keygen") {
    const { values } = parseArgs({
      args,
      options: { out: { type: "string" } },
    });
    const out = values.out ?? DEFAULT_KEY;
    const { did } = generateKeyFile(out);
    // did:key is public information; the private key stays in the file.
    console.log(did);
    console.error(`private key written to ${out} (chmod 600). Back up that directory offline; without it this identity is unrecoverable.`);
    return;
  }

  if (cmd === "serve") {
    const { values } = parseArgs({
      args,
      options: {
        key: { type: "string" },
        "enable-write": { type: "boolean", default: false },
        "base-url": { type: "string" },
        "nonce-state": { type: "string" },
      },
    });
    const keyFile = values.key ?? process.env["TECHNOCORE_KEY_FILE"];
    const baseUrl = values["base-url"] ?? process.env["TECHNOCORE_BASE_URL"];
    await runStdio({
      enableWrite: values["enable-write"] ?? false,
      ...(keyFile ? { keyFile } : {}),
      ...(baseUrl ? { baseUrl } : {}),
      nonceStatePath:
        values["nonce-state"] ?? process.env["TECHNOCORE_NONCE_STATE"] ?? DEFAULT_NONCE_STATE,
    });
    return;
  }

  usage();
  process.exitCode = 2;
}

main().catch((err: unknown) => {
  // Errors never include key material (see crypto/keys.ts contract).
  console.error(`[technocore-mcp] ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
