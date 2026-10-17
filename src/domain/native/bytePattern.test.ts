import { describe, expect, it } from "vitest";
import { parseBytePattern, byteSearchResultSchema } from "./bytePattern.js";

it.each(["0x20", "overlay:0x10", "invalid"])(
  "rejects a match outside reported searched coverage: %s",
  (address) => {
    const page = {
      matches: [
        { address, segment: ".text", file_offset: null, procedure: null },
      ],
      searched: {
        blocks: [{ segment: ".text", start: "0x10", end: "0x1f", bytes: 16 }],
        bytes: 16,
        skipped_uninitialized: [],
        skipped_not_loaded: [],
      },
      complete: true,
      next_cursor: null,
    };
    expect(byteSearchResultSchema.safeParse(page).success).toBe(false);
    page.matches[0]!.address = "0x10";
    expect(byteSearchResultSchema.safeParse(page).success).toBe(true);
    page.matches[0]!.segment = ".bss";
    expect(byteSearchResultSchema.safeParse(page).success).toBe(false);
  },
);

it.each(["", "overlay:"])(
  "accepts matches at both inclusive coverage boundaries in address space %s",
  (space) => {
    const start = `${space}0x10`;
    const end = `${space}0x1f`;
    expect(
      byteSearchResultSchema.safeParse({
        matches: [start, end].map((address) => ({
          address,
          segment: ".text",
          file_offset: null,
          procedure: null,
        })),
        searched: {
          blocks: [{ segment: ".text", start, end, bytes: 16 }],
          bytes: 16,
          skipped_uninitialized: [],
          skipped_not_loaded: [],
        },
        complete: true,
        next_cursor: null,
      }).success,
    ).toBe(true);
  },
);

describe("masked byte patterns", () => {
  it("preserves whole-byte wildcards and combines explicit bit masks", () => {
    const parsed = parseBytePattern("48 8b\t??89", "ff f0 ff 0f");
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value).toEqual({
      bytes: [0x48, 0x8b, 0, 0x89],
      masks: [255, 240, 0, 15],
    });
    const exact = parseBytePattern("Aa\u00a000");
    if (!exact.ok) throw exact.error;
    expect(exact.value).toEqual({ bytes: [170, 0], masks: [255, 255] });
  });

  it.each([
    ["", undefined, "pattern"],
    ["4", undefined, "pattern"],
    ["4?", undefined, "pattern"],
    ["gg", undefined, "pattern"],
    ["?? ??", undefined, "pattern"],
    ["ff", "00", "pattern"],
    ["ffff", "ff", "mask"],
    ["ff", "??", "mask"],
  ])("rejects invalid pattern %s with typed issues", (pattern, mask, field) => {
    const parsed = parseBytePattern(pattern, mask);
    if (parsed.ok) throw new Error("Expected a rejected pattern");
    expect(parsed.error.issues).toMatchObject([
      { path: [field], reason: "invalid_value" },
    ]);
  });
});
