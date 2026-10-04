import { describe, expect, it } from "vitest";
import { actionName, className, cx, endpoint, fmtAgo, fmtBytes, fmtCompact, fmtInt, pct, severityName } from "./format";
import { eventHref, href, parseHash } from "./router";

describe("format", () => {
  it("formats integers and null as an em dash (never a fabricated 0)", () => {
    expect(fmtInt(1234567)).toBe("1,234,567");
    expect(fmtInt(null)).toBe("—");
    expect(fmtInt(undefined)).toBe("—");
  });
  it("compacts and sizes", () => {
    expect(fmtCompact(1_500_000)).toBe("1.50M");
    expect(fmtBytes(2048)).toMatch(/2(\.0)?\s?(KiB|KB)/i);
    expect(fmtCompact(null)).toBe("—");
  });
  it("percentages", () => {
    expect(pct(0.9876)).toBe("98.8%");
    expect(pct(0.9876, 2)).toBe("98.76%");
    expect(pct(null)).toBe("—");
  });
  it("names OCSF enums with a safe fallback", () => {
    expect(severityName(5)).toBe("Critical");
    expect(severityName(null)).toBe("—");
    expect(actionName(2)).toBe("Denied");
    expect(actionName(9)).toBe("action 9");
    expect(className(4001)).toBeTruthy();
    expect(className(999999)).toBe("class 999999");
  });
  it("endpoint and cx helpers", () => {
    expect(endpoint("10.0.0.1", 443)).toBe("10.0.0.1:443");
    expect(endpoint("10.0.0.1", null)).toBe("10.0.0.1");
    expect(endpoint(null, null)).toBe("—");
    expect(cx("a", false, null, "b")).toBe("a b");
  });
  it("fmtAgo is relative to the supplied clock", () => {
    expect(fmtAgo(null)).toBe("never");
    expect(fmtAgo(1_000_000 - 5_000, 1_000_000)).toMatch(/5\s?s/);
  });
});

describe("router", () => {
  it("defaults to /live", () => {
    expect(parseHash("").segments).toEqual(["live"]);
  });
  it("parses path segments and query params", () => {
    const r = parseHash("#/explorer?q=src_ip%3A1.2.3.4");
    expect(r.segments).toEqual(["explorer"]);
    expect(r.params.get("q")).toBe("src_ip:1.2.3.4");
  });
  it("round-trips event ids containing ':' and '/'", () => {
    const id = "01a1:0/x";
    const r = parseHash(eventHref(id));
    expect(r.segments[0]).toBe("event");
    expect(decodeURIComponent(r.segments[1] ?? "")).toBe(id);
  });
  it("href drops undefined params", () => {
    expect(href("/explorer", { q: "a b", x: undefined })).toBe("#/explorer?q=a+b");
  });
});
