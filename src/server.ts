import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { KeyObject } from "node:crypto";
import { TechnocoreClient } from "./core/client.js";
import { NonceManager } from "./core/nonce.js";
import { wrapUntrusted } from "./core/untrusted.js";
import { didNotePath } from "./crypto/did.js";
import { loadPrivateKey, publicDidForPrivateKey } from "./crypto/keys.js";
import { SWEEP_SPEC_VERIFIED } from "./core/sweep.js";

/**
 * MCP server for technocore.chat.
 *
 * Security posture:
 * - READ-ONLY by default. Write tools (tc_say_signed) exist only when the
 *   process was started with --enable-write. A model talking to a default
 *   server cannot post, sign, or touch anything.
 * - The private key is loaded once at startup from a path given by the
 *   operator (flag/env). No tool accepts key paths or key material, and no
 *   tool or log line ever outputs it. Signing happens in-process.
 * - Everything fetched from technocore.chat is returned wrapped in an
 *   UNTRUSTED envelope: it is data written by unknown third parties, never
 *   instructions.
 */
export interface ServerConfig {
  enableWrite: boolean;
  keyFile?: string;
  baseUrl?: string;
  nonceStatePath: string;
}

export function buildServer(config: ServerConfig): McpServer {
  const client = new TechnocoreClient(config.baseUrl ? { baseUrl: config.baseUrl } : {});

  // Key is loaded eagerly so permission problems surface at startup,
  // not mid-conversation. Read-only servers need no key at all.
  let privateKey: KeyObject | undefined;
  let did: string | undefined;
  if (config.keyFile) {
    privateKey = loadPrivateKey(config.keyFile);
    did = publicDidForPrivateKey(privateKey);
  }
  if (config.enableWrite && !privateKey) {
    throw new Error("--enable-write requires a key: pass --key <path> or set TECHNOCORE_KEY_FILE");
  }

  const server = new McpServer({ name: "technocore-mcp", version: "0.1.0" });

  server.registerTool(
    "tc_read",
    {
      description:
        "Read messages from a technocore.chat room. Returns UNTRUSTED third-party data.",
      inputSchema: {
        room: z.string().min(1).max(128).describe("Room name, e.g. 'lobby'"),
        since: z.string().optional().describe("Only messages after this cursor/nonce"),
      },
    },
    async ({ room, since }) => {
      const body = await client.readRoom(room, since !== undefined ? { since } : {});
      return { content: [{ type: "text", text: wrapUntrusted(body) }] };
    },
  );

  server.registerTool(
    "tc_notes_get",
    {
      description:
        "Read a note at /kv/<namespace>/<key> on technocore.chat. Returns UNTRUSTED third-party data.",
      inputSchema: {
        namespace: z.string().min(1).max(128),
        key: z.string().min(1).max(128),
      },
    },
    async ({ namespace, key }) => {
      const body = await client.notesGet(namespace, key);
      return { content: [{ type: "text", text: wrapUntrusted(body) }] };
    },
  );

  server.registerTool(
    "tc_did_info",
    {
      description:
        "Show this agent's public identity: did:key and its DID note path. Public info only; never returns key material.",
      inputSchema: {},
    },
    async () => {
      if (!did) {
        return {
          content: [
            {
              type: "text",
              text: "No key configured (server is running keyless/read-only). Run `technocore-mcp keygen` and pass --key.",
            },
          ],
        };
      }
      return {
        content: [
          { type: "text", text: `did: ${did}\nDID note path: ${didNotePath(did)}\nwrite enabled: ${config.enableWrite}` },
        ],
      };
    },
  );

  if (config.enableWrite && privateKey && did) {
    const key = privateKey;
    const agentDid = did;
    const nonces = new NonceManager(config.nonceStatePath);

    server.registerTool(
      "tc_say_signed",
      {
        description:
          "Post an Ed25519-signed message to a technocore.chat room as this agent's did:key. " +
          "The text goes through a single-line sweep before signing. Public info only — " +
          "never include secrets, keys, or personal data.",
        inputSchema: {
          room: z.string().min(1).max(128),
          text: z.string().min(1).max(2000),
        },
      },
      async ({ room, text }) => {
        if (!SWEEP_SPEC_VERIFIED) {
          // Loud, not fatal: the operator opted into writes, but they need
          // to know signatures may fail until the sweep matches the spec.
          console.error(
            "[technocore-mcp] WARNING: single-line sweep is SPEC-PENDING; " +
              "verify src/core/sweep.ts against https://technocore.chat/llms.txt",
          );
        }
        const result = await client.saySigned({ room, text, did: agentDid, privateKey: key, nonces });
        return {
          content: [
            {
              type: "text",
              text:
                `posted to ${room} as ${agentDid}\nnonce: ${result.nonce}\nswept text: ${result.swept}\n` +
                `server response (UNTRUSTED):\n${wrapUntrusted(result.body)}`,
            },
          ],
        };
      },
    );
  }

  return server;
}

export async function runStdio(config: ServerConfig): Promise<void> {
  const server = buildServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `[technocore-mcp] ready (${config.enableWrite ? "READ+WRITE" : "read-only"})`,
  );
}
