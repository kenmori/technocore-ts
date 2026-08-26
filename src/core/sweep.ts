/**
 * Single-line sweep.
 *
 * !! SPEC-PENDING !!
 * technocore.chat signs the UTF-8 bytes of `<room>|<nonce>|<text>` where
 * `text` is the message AFTER the server's "single-line sweep". The exact
 * sweep algorithm is defined by the official spec (https://technocore.chat/llms.txt)
 * and MUST be verified against it before signed writes are trusted: if this
 * function differs from the server by even one byte, every signature check
 * fails.
 *
 * The PROVISIONAL implementation below is the most conservative common
 * reading: collapse every run of whitespace and C0 control characters
 * (including CR/LF/TAB) into a single ASCII space, then trim. No Unicode
 * normalization. Verify against the spec and the live server before
 * relying on it (see test/sweep.test.ts for the pending matrix).
 */
export const SWEEP_SPEC_VERIFIED = false;

export function sweepSingleLine(text: string): string {
  return text.replace(/[\s\u0000-\u001f\u007f]+/g, " ").trim();
}
