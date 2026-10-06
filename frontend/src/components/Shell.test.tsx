import { render, screen } from "@testing-library/react";
import { Shell } from "./Shell";

test("renders brand and nav", () => {
  render(
    <Shell>
      <div>content</div>
    </Shell>,
  );
  expect(screen.getByText("content")).toBeInTheDocument();
  expect(screen.getByLabelText("Findings")).toBeInTheDocument();
});

test("has no inert placeholder controls", () => {
  render(<Shell />);
  expect(screen.queryByLabelText("Search")).not.toBeInTheDocument();
  expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Settings")).not.toBeInTheDocument();
  expect(screen.queryByText("DL")).not.toBeInTheDocument();
});

test("keeps the five working rail buttons", () => {
  render(<Shell />);
  for (const name of ["Overview", "Findings", "Approval gates", "Report", "Audit"]) {
    expect(screen.getByRole("button", { name })).toBeInTheDocument();
  }
  expect(screen.getAllByRole("button")).toHaveLength(5);
});

test("status dot is neutral when no engagement is loaded", () => {
  const { container } = render(<Shell />);
  expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument();
  expect(container.querySelector(".dot")).toHaveClass("idle");
});

test("status dot is not idle once an engagement is loaded", () => {
  const { container } = render(<Shell status="engagement: x" />);
  expect(screen.getByText(/engagement: x/)).toBeInTheDocument();
  expect(container.querySelector(".dot")).not.toHaveClass("idle");
});

test("exposes a visually hidden Ascent Console heading", () => {
  render(<Shell />);
  const h1 = screen.getByRole("heading", { level: 1, name: "Ascent Console" });
  expect(h1).toHaveClass("sr-only");
});
