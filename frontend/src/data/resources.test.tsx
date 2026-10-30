import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { RESOURCE_KEYS, __resetResourceCache, useResource, useStaleResource } from "./resources";

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

  test("a consumer served from the cache keeps its data if the entry is later evicted", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({ name: "v0" }));
    const first = renderHook(() => useResource("engagement", 0));
    await waitFor(() => expect(first.result.current.status).toBe("ready"));
    first.unmount();

    // Mounts on the cached v0: ready on first render, no request of its own.
    const mounted = renderHook(() => useResource("engagement", 0));
    expect(mounted.result.current).toEqual({ status: "ready", data: { name: "v0" } });

    // Evict the entry (cache reset), then force a re-render of the mounted consumer.
    __resetResourceCache();
    mounted.rerender();
    expect(mounted.result.current).toEqual({ status: "ready", data: { name: "v0" } });
  });

  test("a newer-version fetch that evicts v0 does not regress a mounted v0 consumer", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({ name: "v0" }))
      .mockResolvedValueOnce(json({ error: "x" }, 500));
    const seed = renderHook(() => useResource("engagement", 0));
    await waitFor(() => expect(seed.result.current.status).toBe("ready"));
    seed.unmount();

    const old = renderHook(() => useResource("engagement", 0)); // from the cache
    const newer = renderHook(() => useResource("engagement", 1)); // evicts v0, then fails
    await waitFor(() => expect(newer.result.current.status).toBe("error"));
    old.rerender();
    expect(old.result.current).toEqual({ status: "ready", data: { name: "v0" } });
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

describe("retry", () => {
  test("a retry refreshes every other consumer that is showing the same failure", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({}, 500))
      .mockResolvedValueOnce(json([{ id: "g1" }]));
    const a = renderHook(() => useResource("gates"));
    const b = renderHook(() => useResource("gates"));
    await waitFor(() => expect(a.result.current.status).toBe("error"));
    await waitFor(() => expect(b.result.current.status).toBe("error"));
    act(() => {
      if (a.result.current.status === "error") a.result.current.retry();
    });
    await waitFor(() => expect(a.result.current.status).toBe("ready"));
    // b did not click Retry, but it must not be stuck on the old failure.
    await waitFor(() => expect(b.result.current.status).toBe("ready"));
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test("a retry of one key leaves consumers of other keys alone", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      String(input) === "/api/gates" ? json({}, 500) : json({ name: "lab" }),
    );
    const g = renderHook(() => useResource("gates"));
    const e = renderHook(() => useResource("engagement"));
    await waitFor(() => expect(g.result.current.status).toBe("error"));
    await waitFor(() => expect(e.result.current.status).toBe("ready"));
    act(() => {
      if (g.result.current.status === "error") g.result.current.retry();
    });
    expect(e.result.current.status).toBe("ready");
    // The retried request fails again; let it settle inside the test.
    await waitFor(() => expect(g.result.current.status).toBe("error"));
  });
});

describe("useStaleResource", () => {
  test("keeps the last data while a newer version loads, then swaps it in place", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({ name: "one" }))
      .mockResolvedValueOnce(json({ name: "two" }));
    const { result, rerender } = renderHook(({ v }) => useStaleResource("engagement", v), {
      initialProps: { v: 0 },
    });
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current).toEqual({ status: "ready", data: { name: "one" } }));
    rerender({ v: 1 });
    // No skeleton flash: the old payload is still served while the refetch is in flight.
    expect(result.current).toEqual({ status: "ready", data: { name: "one" } });
    await waitFor(() => expect(result.current).toEqual({ status: "ready", data: { name: "two" } }));
  });

  test("a failed refetch shows the error, and Retry recovers", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json({ name: "one" }))
      .mockResolvedValueOnce(json({}, 500))
      .mockResolvedValueOnce(json({ name: "three" }));
    const { result, rerender } = renderHook(({ v }) => useStaleResource("engagement", v), {
      initialProps: { v: 0 },
    });
    await waitFor(() => expect(result.current.status).toBe("ready"));
    rerender({ v: 1 });
    await waitFor(() => expect(result.current.status).toBe("error"));
    act(() => {
      if (result.current.status === "error") result.current.retry();
    });
    // After an error there is nothing stale worth showing: back to a plain loading state.
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current).toEqual({ status: "ready", data: { name: "three" } }));
  });

  test("a first load is a plain loading state and an initial failure is an error", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}, 500));
    const { result } = renderHook(() => useStaleResource("gates"));
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current.status).toBe("error"));
  });
});

test("RESOURCE_KEYS lists the six keys of the spec", () => {
  expect([...RESOURCE_KEYS].sort()).toEqual(
    ["audit", "engagement", "findings", "gate", "gates", "report"].sort(),
  );
});
