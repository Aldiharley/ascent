import { render } from "@testing-library/react";
import { expect, test } from "vitest";
import { Mascot } from "./Mascot";

test("renders an aria-hidden span, never an img", () => {
  const { container } = render(<Mascot pose="hero" size={232} />);
  const el = container.firstElementChild as HTMLElement;
  expect(el.tagName).toBe("SPAN");
  expect(el).toHaveAttribute("aria-hidden", "true");
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("[src]")).toBeNull();
});

test("the pose and size come through as a class and inline dimensions", () => {
  const { container } = render(<Mascot pose="puzzled" size={96} />);
  const el = container.firstElementChild as HTMLElement;
  expect(el).toHaveClass("mascot", "mascot--puzzled");
  expect(el.style.width).toBe("96px");
  expect(el.style.height).toBe("96px");
});

test("float adds the idle-float modifier only when asked", () => {
  const a = render(<Mascot pose="hero" size={10} float />);
  expect(a.container.firstElementChild).toHaveClass("mascot--float");
  const b = render(<Mascot pose="hero" size={10} />);
  expect(b.container.firstElementChild).not.toHaveClass("mascot--float");
});

test("an unknown pose falls back to rest, so a class never comes from data", () => {
  const { container } = render(<Mascot pose={'evil" onerror="x' as never} size={10} />);
  const el = container.firstElementChild as HTMLElement;
  expect(el.className).toBe("mascot mascot--rest");
});

test("inherited object keys are not poses: 'constructor' falls back to rest", () => {
  const { container } = render(<Mascot pose={"constructor" as never} size={10} />);
  expect((container.firstElementChild as HTMLElement).className).toBe("mascot mascot--rest");
});

test("carries no text for assistive tech", () => {
  const { container } = render(<Mascot pose="rest" size={96} />);
  expect(container).toHaveTextContent("");
});
