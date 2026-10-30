import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { NewScan } from "./NewScan";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function created(over: Record<string, unknown> = {}) {
  return {
    ok: true,
    name: "Acme",
    path: "engagements/acme.yaml",
    scope: { hosts: ["example.com"], cidrs: ["10.0.0.0/24"], urls: ["http://localhost:3000/"] },
    source: "",
    run_command: "ascent run --engagement engagements/acme.yaml --out out",
    ...over,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("creating a scan posts parsed targets with the CSRF header and shows the run command", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  const onCreated = vi.fn();
  render(<NewScan onCreated={onCreated} />);

  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), {
    target: { value: "example.com\n\n  10.0.0.0/24  \nhttp://localhost:3000/\n" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
  expect(
    screen.getByText("ascent run --engagement engagements/acme.yaml --out out"),
  ).toBeInTheDocument();
  expect(onCreated).toHaveBeenCalledTimes(1);

  // Posted with the right method/header and blank lines dropped + trimmed.
  const [url, init] = spy.mock.calls[0];
  expect(url).toBe("/api/engagements");
  expect(init?.method).toBe("POST");
  expect((init?.headers as Record<string, string>)["X-Ascent"]).toBe("1");
  const sent = JSON.parse(init?.body as string);
  expect(sent.name).toBe("Acme");
  expect(sent.targets).toEqual(["example.com", "10.0.0.0/24", "http://localhost:3000/"]);
});

test("rejected targets are listed and no success card is shown", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(
      {
        ok: false,
        error: "these targets are not valid, unambiguous in-scope entries",
        rejected: ["evil.com/path", "exa mple.com"],
      },
      422,
    ),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), {
    target: { value: "evil.com/path\nexa mple.com" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/not valid, unambiguous/);
  expect(screen.getByText("evil.com/path")).toBeInTheDocument();
  expect(screen.getByText("exa mple.com")).toBeInTheDocument();
  expect(screen.queryByText(/Scan defined/)).not.toBeInTheDocument();
});

test("a source-not-found error is surfaced to the user", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json({ ok: false, error: "source path not found: ./nope", field: "source" }, 422),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.change(screen.getByLabelText(/Source directory/), { target: { value: "./nope" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/source path not found: \.\/nope/),
  );
});
