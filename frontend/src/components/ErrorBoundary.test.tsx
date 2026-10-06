import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

afterEach(() => {
  vi.restoreAllMocks();
});

test("shows an alert when a child throws and Try again re-mounts the children", () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  // React 18 re-renders once after a throw, so gate on a flag rather than a render count.
  let broken = true;
  function Flaky() {
    if (broken) throw new Error("boom");
    return <p>recovered</p>;
  }
  render(
    <ErrorBoundary>
      <Flaky />
    </ErrorBoundary>,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("This view failed to render.");
  broken = false;
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(screen.getByText("recovered")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
