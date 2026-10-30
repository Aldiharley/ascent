import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { RESOURCE_KEYS, __resetResourceCache, useResource } from "./resources";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useResource", () => {
  test("goes loading -> ready with the parsed data", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({ name: "lab" }));
    const { result } = renderHook(() => useResource("engagement"));
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(result.current).toEqual({ status: "ready", data: { name: "lab" } });
  });

  test("two consumers of the same key and version share one request", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([]));
    const a = renderHook(() => useResource("gates"));
    const b = renderHook(() => useResource("gates"));
    await waitFor(() => expect(a.result.current.status).toBe("ready"));
    await waitFor(() => expect(b.result.current.status).toBe("ready"));
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("a remount is served from the cache: ready on first render, no second request", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([]));
    const first = renderHook(() => useResource("gates"));
    await waitFor(() => expect(first.result.current.status).toBe("ready"));
    first.unmount();
    const second = renderHook(() => useResource("gates"));
    expect(second.result.current.status).toBe("ready");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test("different keys fetch their own endpoint", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      return path === "/api/audit" ? json({ entries: [], chain_ok: true }) : json([]);
    });
    const a = renderHook(() => useResource("audit"));
    const g = renderHook(() => useResource("gates"));
    await waitFor(() => expect(a.result.current.status).toBe("ready"));
    await waitFor(() => expect(g.result.current.status).toBe("ready"));
    expect(spy.mock.calls.map((c) => String(c[0])).sort()).toEqual(["/api/audit", "/api/gates"]);
  });

  test("bumping the version refetches", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({ name: "one" }))
      .mockResolvedValueOnce(json({ name: "two" }));
    const { result, rerender } = renderHook(({ v }) => useResource("engagement", v), {
      initialProps: { v: 0 },
    });
    await waitFor(() => expect(result.current.status).toBe("ready"));
    rerender({ v: 1 });
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current).toEqual({ status: "ready", data: { name: "two" } }));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test("__resetResourceCache drops everything so the next mount fetches again", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([]));
    const first = renderHook(() => useResource("gates"));
    await waitFor(() => expect(first.result.current.status).toBe("ready"));
    first.unmount();
    __resetResourceCache();
    const second = renderHook(() => useResource("gates"));
    expect(second.result.current.status).toBe("loading");
    await waitFor(() => expect(second.result.current.status).toBe("ready"));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test("a failed request reports error with a retry that refetches", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({}, 500))
      .mockResolvedValueOnce(json([]));
    const { result } = renderHook(() => useResource("gates"));
    await waitFor(() => expect(result.current.status).toBe("error"));
    act(() => {
      if (result.current.status === "error") result.current.retry();
    });
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current).toEqual({ status: "ready", data: [] }));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test("errors are not cached: a later mount tries again", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({}, 500))
      .mockResolvedValueOnce(json([]));
    const first = renderHook(() => useResource("gates"));
    await waitFor(() => expect(first.result.current.status).toBe("error"));
    first.unmount();
    const second = renderHook(() => useResource("gates"));
    await waitFor(() => expect(second.result.current.status).toBe("ready"));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test("the error state carries no error text from the response", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({ error: "<b>boom</b>" }, 500));
    const { result } = renderHook(() => useResource("gates"));
    await waitFor(() => expect(result.current.status).toBe("error"));
    expect(Object.keys(result.current).sort()).toEqual(["retry", "status"]);
  });

  test("unmounting before the response settles does not warn", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let resolve!: (r: Response) => void;
    vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise<Response>((r) => (resolve = r)));
    const { unmount } = renderHook(() => useResource("gates"));
    unmount();
    resolve(json([]));
    await new Promise((r) => setTimeout(r, 0));
    expect(errors).not.toHaveBeenCalled();
  });
});

test("RESOURCE_KEYS lists the six keys of the spec", () => {
  expect([...RESOURCE_KEYS].sort()).toEqual(
    ["audit", "engagement", "findings", "gate", "gates", "report"].sort(),
  );
});
