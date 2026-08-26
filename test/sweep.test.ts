import { test } from "node:test";
import assert from "node:assert/strict";
import { sweepSingleLine, SWEEP_SPEC_VERIFIED } from "../src/index.js";

/**
 * The sweep is SPEC-PENDING (see src/core/sweep.ts). These tests pin the
 * PROVISIONAL behavior so accidental changes are caught; the `todo` block
 * at the bottom is the matrix to fill in from https://technocore.chat/llms.txt
 * before signed writes are trusted.
 */

test("provisional: newlines/tabs collapse to single spaces", () => {
  assert.equal(sweepSingleLine("a\nb"), "a b");
  assert.equal(sweepSingleLine("a\r\n\tb"), "a b");
  assert.equal(sweepSingleLine("a \n \n b"), "a b");
});

test("provisional: trims ends, collapses runs", () => {
  assert.equal(sweepSingleLine("  hello   world  "), "hello world");
  assert.equal(sweepSingleLine("\n\nx\n\n"), "x");
});

test("provisional: non-ASCII text passes through untouched", () => {
  assert.equal(sweepSingleLine("日本語のテキスト"), "日本語のテキスト");
  assert.equal(sweepSingleLine("emoji 🎉 ok"), "emoji 🎉 ok");
});

test("provisional: pipes and URL-special chars are preserved", () => {
  assert.equal(sweepSingleLine("a|b/c%d#e"), "a|b/c%d#e");
});

test("sweep spec flag is still pending", () => {
  // Flip SWEEP_SPEC_VERIFIED to true ONLY after the todo matrix below is
  // filled in from the official spec and verified against the live server.
  assert.equal(SWEEP_SPEC_VERIFIED, false);
});

// ---- SPEC VERIFICATION MATRIX (fill in from llms.txt, then implement) ----
test.todo("spec: exact CR/LF handling (space? strip? collapse?)");
test.todo("spec: tab handling");
test.todo("spec: leading/trailing whitespace");
test.todo("spec: consecutive spaces (collapsed or preserved?)");
test.todo("spec: Unicode whitespace (U+00A0, U+3000, ...)");
test.todo("spec: Unicode normalization (NFC or none)");
test.todo("spec: control characters (stripped or replaced?)");
test.todo("spec: max length / truncation before or after sweep");
test.todo("live: signed post accepted by server verifies with this sweep");
