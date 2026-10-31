import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { __resetResourceCache } from "../data/resources";
import { Report } from "./Report";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function mockReport(markdown: string) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ markdown }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("renders headings and text, with a visible title (not an h1)", async () => {
  mockReport("# Ascent report: demo\n\n## Findings\n\nSome **bold** text.\n");
  const { container } = render(<Report />);
  const title = await screen.findByText("Ascent report: demo");
  expect(title.tagName).not.toBe("H1");
  expect(title).toHaveClass("report-title");
  expect(container.querySelector("h1")).toBeNull();
  expect(screen.getByRole("heading", { level: 2, name: "Findings" })).toBeInTheDocument();
  expect(screen.getByText("bold").tagName).toBe("STRONG");
});

test("raw HTML in the markdown creates no script or img elements", async () => {
  mockReport("hello\n\n<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\nbye");
  const { container } = render(<Report />);
  await screen.findByText(/hello/);
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("[onerror]")).toBeNull();
});

test("markdown image syntax creates no img element (no beaconing)", async () => {
  mockReport("before\n\n![x](http://attacker.example/leak)\n\nafter");
  const { container } = render(<Report />);
  await screen.findByText(/before/);
  expect(container.querySelector("img")).toBeNull();
  expect(container.innerHTML).not.toContain("attacker.example");
});

test("a javascript: link has no javascript: href", async () => {
  mockReport("[click](javascript:alert(1))");
  const { container } = render(<Report />);
  await screen.findByText("click");
  for (const a of Array.from(container.querySelectorAll("a"))) {
    expect(a.getAttribute("href") ?? "").not.toMatch(/^\s*javascript:/i);
  }
});

test("safe links open in a new tab with noopener noreferrer", async () => {
  mockReport("[docs](https://example.com/x)");
  render(<Report />);
  const a = await screen.findByRole("link", { name: "docs" });
  expect(a).toHaveAttribute("href", "https://example.com/x");
  expect(a).toHaveAttribute("target", "_blank");
  expect(a).toHaveAttribute("rel", "noopener noreferrer");
});

test("empty state when there is no report yet", async () => {
  mockReport("");
  render(<Report />);
  expect(await screen.findByText(/No report yet/i)).toBeInTheDocument();
});

test("error state when the request fails", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}, 500));
  render(<Report />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load/i);
});

test("a new version refetches and swaps the report in place, without a loading flash", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json({ markdown: "## First body" }))
    .mockResolvedValueOnce(json({ markdown: "## Second body" }));
  const { rerender } = render(<Report version={0} />);
  // (the heading text also appears once in the section index, so look the heading up by role)
  await screen.findByRole("heading", { level: 2, name: "First body" });
  rerender(<Report version={1} />);
  expect(screen.getByRole("heading", { level: 2, name: "First body" })).toBeInTheDocument();
  expect(screen.queryByText("Loading report…")).toBeNull();
  expect(await screen.findByRole("heading", { level: 2, name: "Second body" })).toBeInTheDocument();
  // the index follows the new body
  const nav = screen.getByRole("navigation", { name: "Report sections" });
  expect(within(nav).getByRole("link", { name: "Second body" })).toBeInTheDocument();
  expect(within(nav).queryByRole("link", { name: "First body" })).toBeNull();
});

// ---------------------------------------------------------------------------------------------
// Task 6: the reading card and the section index.
// ---------------------------------------------------------------------------------------------

const DOC = "# Ascent report: demo\n\nintro\n\n## Summary\n\ntext\n\n## DAST coverage\n\nmore\n\n## Summary\n\nagain\n";

test("the report is one reading card with the report class; no legacy glass or panel; no mascot", async () => {
  mockReport(DOC);
  const { container } = render(<Report />);
  await screen.findByText("Ascent report: demo");
  const card = container.querySelector(".report-layout > .card.report") as HTMLElement;
  expect(card).not.toBeNull();
  expect(card.querySelector(".report-title")).not.toBeNull();
  expect(container.querySelector(".glass, .panel, .phead, .ptitle")).toBeNull();
  expect(container.querySelector(".mascot")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
});

test("the section index lists every h2 as text, in order, with internal #r- links and no target", async () => {
  mockReport(DOC);
  render(<Report />);
  const nav = await screen.findByRole("navigation", { name: "Report sections" });
  expect(within(nav).getByText("On this page")).toBeInTheDocument();
  const links = within(nav).getAllByRole("link");
  expect(links.map((a) => a.textContent)).toEqual(["Summary", "DAST coverage", "Summary"]);
  expect(links.map((a) => a.getAttribute("href"))).toEqual(["#r-summary", "#r-dast-coverage", "#r-summary-2"]);
  for (const a of links) {
    expect(a).not.toHaveAttribute("target");
    expect(a).not.toHaveAttribute("rel");
  }
});

test("each h2 gets the id its index link points at", async () => {
  mockReport(DOC);
  const { container } = render(<Report />);
  const nav = await screen.findByRole("navigation", { name: "Report sections" });
  const h2s = Array.from(container.querySelectorAll(".report h2"));
  expect(h2s.map((h) => h.id)).toEqual(["r-summary", "r-dast-coverage", "r-summary-2"]);
  for (const a of within(nav).getAllByRole("link")) {
    const id = (a.getAttribute("href") as string).slice(1);
    expect(container.querySelector(`#${id}`)?.tagName).toBe("H2");
  }
});

test("a hostile heading is index text only, and the id stays within [a-z0-9-]", async () => {
  mockReport("## <b>x</b> & \"q\" `code` <img src=x onerror=alert(1)>\n\ntext\n\n## !!!\n");
  const { container } = render(<Report />);
  const nav = await screen.findByRole("navigation", { name: "Report sections" });
  expect(nav.querySelector("b, img, code, script")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("[onerror]")).toBeNull();
  for (const a of within(nav).getAllByRole("link")) {
    expect(a.getAttribute("href")).toMatch(/^#r-[a-z0-9-]+$/);
  }
  for (const h of Array.from(container.querySelectorAll(".report h2"))) {
    expect(h.id).toMatch(/^r-[a-z0-9-]+$/);
  }
});

test("no index when the report has no h2; the report text is still shown", async () => {
  mockReport("# Title only\n\njust a paragraph\n");
  render(<Report />);
  await screen.findByText("just a paragraph");
  expect(screen.queryByRole("navigation", { name: "Report sections" })).toBeNull();
});

type IoCb = (entries: Partial<IntersectionObserverEntry>[]) => void;

/** Stubs IntersectionObserver; resolves to the observed headings and a way to fire the callback. */
function stubObserver() {
  const seen = { cb: (() => {}) as IoCb, observed: [] as Element[], disconnect: vi.fn() };
  vi.stubGlobal(
    "IntersectionObserver",
    class {
      constructor(c: IoCb) {
        seen.cb = c;
      }
      observe(el: Element) {
        seen.observed.push(el);
      }
      unobserve() {}
      disconnect = seen.disconnect;
    },
  );
  return seen;
}

// The observed band is the top 300px of the viewport. Where a heading is when it is not in it:
const IN = { isIntersecting: true };
const band = { top: 0, bottom: 300 } as DOMRectReadOnly;
const ABOVE = { isIntersecting: false, boundingClientRect: { top: -40 } as DOMRectReadOnly, rootBounds: band };
const BELOW = { isIntersecting: false, boundingClientRect: { top: 600 } as DOMRectReadOnly, rootBounds: band };

test("the active section follows an IntersectionObserver; the link is marked aria-current", async () => {
  const io = stubObserver();
  try {
    mockReport(DOC);
    const { unmount } = render(<Report />);
    const nav = await screen.findByRole("navigation", { name: "Report sections" });
    await waitFor(() => expect(io.observed).toHaveLength(3));
    const links = within(nav).getAllByRole("link");
    expect(links.some((a) => a.hasAttribute("aria-current"))).toBe(false);
    act(() => io.cb([{ target: io.observed[1], ...IN }]));
    expect(links[1]).toHaveAttribute("aria-current", "location");
    expect(links[0]).not.toHaveAttribute("aria-current");
    act(() => io.cb([{ target: io.observed[1], ...ABOVE }, { target: io.observed[2], ...IN }]));
    expect(links[2]).toHaveAttribute("aria-current", "location");
    expect(links[1]).not.toHaveAttribute("aria-current");
    unmount();
    expect(io.disconnect).toHaveBeenCalled();
  } finally {
    vi.unstubAllGlobals();
  }
});

test("scrolling back up moves the mark to the section above, and off it above the first heading", async () => {
  const io = stubObserver();
  try {
    mockReport(DOC);
    render(<Report />);
    const nav = await screen.findByRole("navigation", { name: "Report sections" });
    await waitFor(() => expect(io.observed).toHaveLength(3));
    const links = within(nav).getAllByRole("link");
    const current = () => links.map((a) => a.getAttribute("aria-current") === "location");
    // reading the third section: the first two headings have scrolled past the band
    act(() =>
      io.cb([
        { target: io.observed[0], ...ABOVE },
        { target: io.observed[1], ...ABOVE },
        { target: io.observed[2], ...IN },
      ]),
    );
    expect(current()).toEqual([false, false, true]);
    // scroll up: the third heading drops below the band and no heading is in it, so the section being
    // read is the second (this used to leave the third marked until another heading entered)
    act(() => io.cb([{ target: io.observed[2], ...BELOW }]));
    expect(current()).toEqual([false, true, false]);
    act(() => io.cb([{ target: io.observed[1], ...BELOW }]));
    expect(current()).toEqual([true, false, false]);
    // back above the first heading: nothing is being read yet
    act(() => io.cb([{ target: io.observed[0], ...BELOW }]));
    expect(current()).toEqual([false, false, false]);
    // and scrolling down again picks the sections up in order
    act(() => io.cb([{ target: io.observed[0], ...IN }]));
    expect(current()).toEqual([true, false, false]);
    act(() => io.cb([{ target: io.observed[0], ...ABOVE }]));
    expect(current()).toEqual([true, false, false]); // between two headings: the last passed one stays
  } finally {
    vi.unstubAllGlobals();
  }
});

test("opened part-way down, the last heading already passed is the current one", async () => {
  const io = stubObserver();
  try {
    mockReport(DOC);
    render(<Report />);
    const nav = await screen.findByRole("navigation", { name: "Report sections" });
    await waitFor(() => expect(io.observed).toHaveLength(3));
    const links = within(nav).getAllByRole("link");
    act(() =>
      io.cb([
        { target: io.observed[0], ...ABOVE },
        { target: io.observed[1], ...ABOVE },
        { target: io.observed[2], ...BELOW },
      ]),
    );
    expect(links[1]).toHaveAttribute("aria-current", "location");
  } finally {
    vi.unstubAllGlobals();
  }
});

test("empty state: the resting watchdog at 160px and the exact sentence", async () => {
  mockReport("   \n");
  const { container } = render(<Report />);
  expect(await screen.findByText("No report yet. Run a scan to generate one.")).toBeInTheDocument();
  const mascot = container.querySelector(".mascot--rest") as HTMLElement;
  expect(mascot).toHaveAttribute("aria-hidden", "true");
  expect(mascot).toHaveStyle({ width: "160px", height: "160px" });
  expect(container.querySelector("img")).toBeNull();
  expect(screen.queryByRole("navigation", { name: "Report sections" })).toBeNull();
});

test("loading is a status with a visible caption; failure is one alert with Retry", async () => {
  let release!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch").mockReturnValueOnce(new Promise<Response>((res) => (release = res)));
  const { unmount } = render(<Report />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading report…");
  release(json({ markdown: "## Done" }));
  await screen.findByRole("heading", { name: "Done" });
  unmount();

  __resetResourceCache();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500)).mockResolvedValueOnce(json({ markdown: "## Back" }));
  render(<Report />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load the report");
  fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("heading", { name: "Back" })).toBeInTheDocument();
});
