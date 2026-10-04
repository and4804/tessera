import { describe, expect, it } from "vitest";
import { LAKE_FIELDS } from "./fields";
import { applyCompletion, contextAt, isIpish, parseQuery, suggest, tokenize } from "./query-dsl";

const P = (q: string) => parseQuery(q, LAKE_FIELDS);

describe("tokenize", () => {
  it("splits field terms, negation and free text", () => {
    const { terms } = tokenize('src_ip:10.1.1.15 -status:parsed "port scan" bare');
    expect(terms.map((t) => [t.kind, t.field, t.value, t.negated])).toEqual([
      ["field", "src_ip", "10.1.1.15", false],
      ["field", "status", "parsed", true],
      ["text", undefined, "port scan", false],
      ["text", undefined, "bare", false]
    ]);
  });
  it("keeps quoted values with spaces and escapes", () => {
    const { terms } = tokenize('signature:"ET SCAN \\"nmap\\"" x');
    expect(terms[0].value).toBe('ET SCAN "nmap"');
    expect(terms[0].quoted).toBe(true);
    expect(terms[1].value).toBe("x");
  });
  it("parses comparison operators", () => {
    const { terms } = tokenize("bytes_out:>=1000 duration_ms:<50");
    expect(terms.map((t) => [t.op, t.value])).toEqual([[">=", "1000"], ["<", "50"]]);
  });
  it("reports unterminated quotes", () => {
    expect(tokenize('url:"abc').issues[0].message).toMatch(/Unterminated/);
  });
  it("records exact source ranges", () => {
    const q = "a:1  b:2";
    const { terms } = tokenize(q);
    expect(q.slice(terms[1].start, terms[1].end)).toBe("b:2");
  });
});

describe("parseQuery validation", () => {
  it("accepts the guide's example query", () => {
    expect(P('src_ip:10.1.1.15 action:denied dst_port:22 "free text"').issues).toEqual([]);
  });
  it("flags unknown fields with a suggestion", () => {
    const r = P("scr_ip:1.2.3.4");
    expect(r.issues[0].level).toBe("error");
    expect(r.issues[0].message).toContain("src_ip");
  });
  it("validates IPs, CIDR, wildcards and ports", () => {
    expect(P("src_ip:10.0.0.0/8").issues).toEqual([]);
    expect(P("src_ip:10.1.*").issues).toEqual([]);
    expect(P("src_ip:2001:db8::1").issues).toEqual([]);
    expect(P("src_ip:999.1.1.1").issues).toHaveLength(1);
    expect(P("dst_port:70000").issues).toHaveLength(1);
    expect(P("dst_port:abc").issues).toHaveLength(1);
  });
  it("supports lists and ranges for numerics", () => {
    expect(P("dst_port:22,2222,3389").issues).toEqual([]);
    expect(P("bytes_out:1000..5000").issues).toEqual([]);
    expect(P("dst_port:22,,80").issues).toHaveLength(1);
  });
  it("rejects comparison on non-numeric fields", () => {
    expect(P("src_ip:>10.0.0.1").issues.some((i) => /only applies/.test(i.message))).toBe(true);
  });
  it("warns (not errors) on unknown enum values", () => {
    const r = P("status:weird");
    expect(r.issues[0].level).toBe("warning");
  });
  it("flags missing values", () => {
    expect(P("src_ip:").issues[0].message).toMatch(/Missing value/);
  });
  it("never throws on junk", () => {
    for (const q of ['"', "-", ":::", "a:", "-:", "\\", "(((", "x:\"\\"]) expect(() => P(q)).not.toThrow();
  });
});

describe("isIpish", () => {
  it("handles v4/v6/cidr", () => {
    expect(isIpish("192.168.0.1")).toBe(true);
    expect(isIpish("192.168.0.1/33")).toBe(false);
    expect(isIpish("::1")).toBe(true);
    expect(isIpish("2001:db8::/32")).toBe(true);
    expect(isIpish("1:2:3:4:5:6:7:8:9")).toBe(false);
    expect(isIpish("hello")).toBe(false);
  });
});

describe("autocomplete", () => {
  it("completes field names by prefix", () => {
    const q = "src_ip:1.1.1.1 ds";
    const { ctx, items } = suggest(q, q.length, LAKE_FIELDS);
    expect(ctx.kind).toBe("field");
    expect(items.map((i) => i.label)).toContain("dst_ip");
    expect(items.every((i) => i.insert.endsWith(":"))).toBe(true);
  });
  it("completes enum values after the colon", () => {
    const q = "action:de";
    const { ctx, items } = suggest(q, q.length, LAKE_FIELDS);
    expect(ctx.kind).toBe("value");
    expect(items.map((i) => i.label)).toEqual(["denied"]);
  });
  it("completes after a comma in a list and applies the edit in place", () => {
    const fields = [{ name: "status", type: "enum" as const, enum: ["parsed", "partial", "unparsed"] }];
    const q = "status:parsed,pa rest";
    const caret = "status:parsed,pa".length;
    const { ctx, items } = suggest(q, caret, fields);
    expect(ctx.prefix).toBe("pa");
    const out = applyCompletion(q, ctx, items.find((i) => i.label === "partial")!);
    expect(out.text).toBe("status:parsed,partial rest");
  });
  it("offers nothing inside quotes", () => {
    const q = 'url:"abc de';
    expect(contextAt(q, q.length).kind).toBe("none");
  });
  it("merges dynamic values and quotes ones with spaces", () => {
    const q = "device_host:F";
    const { items } = suggest(q, q.length, LAKE_FIELDS, ["FGT-HQ", "Fire Wall"]);
    expect(items.map((i) => i.insert)).toEqual(["FGT-HQ", '"Fire Wall"']);
  });
});
