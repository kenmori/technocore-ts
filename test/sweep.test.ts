import { test } from "node:test";
import assert from "node:assert/strict";
import { sweepSingleLine, SWEEP_SPEC_VERIFIED, MAX_TEXT_CHARS, MAX_VALUE_CHARS } from "../src/index.js";

/**
 * Verified against the server's `clean_text` (flop-labs/technocore-chat,
 * src/store.py, commit 41ecbbb): every character in Unicode categories
 * Cc/Cf/Cs/Co/Zl/Zp becomes ONE space (no run collapsing), then trim.
 * Expected values below were cross-validated against the Python reference:
 *   "".join(" " if unicodedata.category(c) in ("Cc","Cf","Cs","Co","Zl","Zp")
 *           else c for c in text).strip()
 */

test("spec: each invisible char becomes exactly one space — runs NOT collapsed", () => {
  assert.equal(sweepSingleLine("a\nb"), "a b");
  assert.equal(sweepSingleLine("a\n\nb"), "a  b"); // two newlines -> two spaces
  assert.equal(sweepSingleLine("a\r\n\tb"), "a   b"); // CR, LF, TAB -> three spaces
});

test("spec: ordinary spaces (Zs) are NOT swept — consecutive spaces survive", () => {
  assert.equal(sweepSingleLine("a  b"), "a  b");
  assert.equal(sweepSingleLine("a  b"), "a  b"); // NBSP preserved
  assert.equal(sweepSingleLine("a　b"), "a　b"); // ideographic space preserved
});

test("spec: trim both ends (including Zs at the edges)", () => {
  assert.equal(sweepSingleLine("  hello   world  "), "hello   world");
  assert.equal(sweepSingleLine("\n\nx\n\n"), "x");
  assert.equal(sweepSingleLine("　x　"), "x");
});

test("spec: format characters (Cf) — ZWSP, ZWJ, bidi — each become a space", () => {
  assert.equal(sweepSingleLine("a​b"), "a b"); // zero-width space
  assert.equal(sweepSingleLine("a‮b"), "a b"); // RTL override
  // ZWJ family emoji flattens to its parts separated by spaces
  assert.equal(sweepSingleLine("\u{1F468}‍\u{1F469}‍\u{1F467}"), "\u{1F468} \u{1F469} \u{1F467}");
});

test("spec: line/paragraph separators (Zl/Zp) and lone surrogates (Cs)", () => {
  assert.equal(sweepSingleLine("a b c"), "a b c");
  assert.equal(sweepSingleLine("a\ud800b"), "a b"); // lone surrogate
});

test("spec: pure-invisible input sweeps to empty", () => {
  assert.equal(sweepSingleLine("​​"), "");
  assert.equal(sweepSingleLine(" \n\t "), "");
});

test("spec: no Unicode normalization; visible text untouched", () => {
  assert.equal(sweepSingleLine("日本語のテキスト"), "日本語のテキスト");
  assert.equal(sweepSingleLine("a|b/c%d#e"), "a|b/c%d#e");
  const decomposed = "é"; // é as base + combining accent (Mn — not swept)
  assert.equal(sweepSingleLine(decomposed), decomposed);
});

test("spec flag and server-side caps", () => {
  assert.equal(SWEEP_SPEC_VERIFIED, true);
  assert.equal(MAX_TEXT_CHARS, 4096);
  assert.equal(MAX_VALUE_CHARS, 8192);
});

test.todo("live: signed post accepted by the production server (run from a trusted machine)");
