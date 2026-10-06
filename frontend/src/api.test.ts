import { afterEach, expect, test, vi } from "vitest";
import { getAudit, getFindings, getGates } from "./api";

function mockBody(body: unknown) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("getFindings drops null, non-objects and items without an object finding", async () => {
  const good = { finding: { rule_id: "r", severity: "HIGH", title: "t" }, verdict: "TRUE_POSITIVE" };
  mockBody([null, 7, "x", { finding: null }, { verdict: "ABSTAIN" }, { finding: "s" }, good]);
  expect(await getFindings()).toEqual([good]);
});

test("getGates drops items without a string id and duplicate ids (first wins)", async () => {
  const a = { id: "g1", title: "first" };
  const dup = { id: "g1", title: "second" };
  const b = { id: "g2", title: "b" };
  mockBody([null, 3, { title: "no id" }, { id: "" }, { id: 5 }, a, dup, b]);
  expect(await getGates()).toEqual([a, b]);
});

test("getAudit drops entries that are not objects", async () => {
  const e = { ts: "t", entry_hash: "h" };
  mockBody({ entries: [null, 1, "s", e], chain_ok: true });
  expect(await getAudit()).toEqual({ entries: [e], chain_ok: true });
});
