import { describe, expect, it } from "vitest";
import { catalogRawSHA256 } from "../src/main";

describe("catalog validation document identity", () => {
  it("binds identity to exact bytes instead of a path", async () => {
    const encoder = new TextEncoder();
    const first = encoder.encode("# catalog\nvalue=a\n").buffer as ArrayBuffer;
    const same = encoder.encode("# catalog\nvalue=a\n").buffer as ArrayBuffer;
    const changed = encoder.encode("# catalog\nvalue=b\n").buffer as ArrayBuffer;

    expect(await catalogRawSHA256(first)).toBe(await catalogRawSHA256(same));
    expect(await catalogRawSHA256(first)).not.toBe(await catalogRawSHA256(changed));
  });
});
