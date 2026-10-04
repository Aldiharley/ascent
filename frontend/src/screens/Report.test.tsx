import { render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
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
