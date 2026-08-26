import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { didFromPublicKey } from "./did.js";

/**
 * Key handling rules (the security core of this package):
 *
 * - Private keys are referenced by FILE PATH only, never by value in tool
 *   arguments, tool results, logs, or error messages.
 * - Key files must be owner-only (0600). Loading refuses group/world-readable
 *   files instead of silently accepting them.
 * - Nothing in this package serializes a private key back out except
 *   `generateKeyFile`, which writes the file it just created and returns
 *   only the public did:key.
 */

export class KeyPermissionError extends Error {}

function assertOwnerOnly(path: string): void {
  const st = statSync(path);
  if ((st.mode & 0o077) !== 0) {
    throw new KeyPermissionError(
      `refusing to load ${path}: permissions are ${(st.mode & 0o777).toString(8)}, ` +
        `expected owner-only (chmod 600 ${path})`,
    );
  }
}

/** Load an Ed25519 private key (PKCS#8 PEM) from disk. Path comes from config, never from a tool call. */
export function loadPrivateKey(path: string): KeyObject {
  assertOwnerOnly(path);
  const pem = readFileSync(path);
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error(`key at ${path} is ${key.asymmetricKeyType}, expected ed25519`);
    }
    return key;
  } finally {
    pem.fill(0); // drop the plaintext copy promptly
  }
}

export function publicDidForPrivateKey(privateKey: KeyObject): string {
  return didFromPublicKey(createPublicKey(privateKey));
}

/**
 * Generate a new Ed25519 keypair, write the private key to `path`
 * (PKCS#8 PEM, chmod 600, parent dir chmod 700), and return the did:key.
 * Refuses to overwrite an existing file — losing an agent key means losing
 * the identity, so rotation must be a deliberate manual act.
 */
export function generateKeyFile(path: string): { did: string } {
  let exists = true;
  try {
    statSync(path);
  } catch {
    exists = false;
  }
  if (exists) {
    throw new Error(
      `${path} already exists; refusing to overwrite an agent key. Move it aside first if you really mean to rotate.`,
    );
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, pem, { mode: 0o600, flag: "wx" });
  return { did: didFromPublicKey(publicKey) };
}
