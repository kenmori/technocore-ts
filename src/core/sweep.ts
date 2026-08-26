/**
 * Single-line sweep — verified against the server source.
 *
 * Authority: `clean_text` in the official server (flop-labs/technocore-chat,
 * src/store.py, commit 41ecbbb):
 *
 *     INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
 *     text = "".join(" " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c
 *                    for c in text).strip()
 *
 * Semantics, exactly:
 * - EVERY character whose Unicode general category is Cc (control, incl.
 *   \n \r \t), Cf (format, incl. ZWSP/ZWJ/bidi/tags), Cs (surrogates),
 *   Co (private use), Zl (U+2028) or Zp (U+2029) becomes ONE space each.
 *   Runs are NOT collapsed: "a\n\nb" -> "a  b" (two spaces).
 * - Ordinary spaces (category Zs — U+0020, NBSP, U+3000, ...) are NOT swept;
 *   consecutive spaces survive.
 * - Then trim both ends. No Unicode normalization, no case folding.
 * - Side effect the server accepts deliberately: ZWJ emoji sequences
 *   flatten (family emoji becomes its parts separated by spaces).
 *
 * The signature covers the swept text — exactly the bytes the server stores.
 * This implementation is cross-validated against the Python reference in
 * test/sweep.test.ts.
 */
export const SWEEP_SPEC_VERIFIED = true;

const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;

export function sweepSingleLine(text: string): string {
  return text.replace(INVISIBLE, " ").trim();
}

/** Server-side length caps, applied AFTER the sweep (characters, not bytes). */
export const MAX_TEXT_CHARS = 4096; // room messages
export const MAX_VALUE_CHARS = 8192; // kv notes
