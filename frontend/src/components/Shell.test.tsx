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
