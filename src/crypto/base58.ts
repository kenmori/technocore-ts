/**
 * Minimal base58btc (Bitcoin alphabet) encode/decode.
 * No dependencies; operates on Uint8Array.
 */
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP = new Map<string, number>(
  [...ALPHABET].map((c, i) => [c, i]),
);

export function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  // Preserve leading zero bytes as "1"s.
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function base58btcDecode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const v = ALPHABET_MAP.get(c);
    if (v === undefined) throw new Error(`invalid base58 character: ${JSON.stringify(c)}`);
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
