import { describe, expect, test } from "vitest";
import { greeting, timeOfDay } from "./greeting";

function at(h: number, m = 0): Date {
  return new Date(2026, 9, 31, h, m, 0);
}

describe("timeOfDay", () => {
  test("morning is 05:00 to 11:59", () => {
    expect(timeOfDay(at(5, 0))).toBe("morning");
    expect(timeOfDay(at(11, 59))).toBe("morning");
  });
  test("afternoon is 12:00 to 17:59", () => {
    expect(timeOfDay(at(12, 0))).toBe("afternoon");
    expect(timeOfDay(at(17, 59))).toBe("afternoon");
  });
  test("evening is 18:00 to 04:59", () => {
    expect(timeOfDay(at(18, 0))).toBe("evening");
    expect(timeOfDay(at(23, 59))).toBe("evening");
    expect(timeOfDay(at(0, 0))).toBe("evening");
    expect(timeOfDay(at(4, 59))).toBe("evening");
  });
  test("defaults to the current time", () => {
    expect(["morning", "afternoon", "evening"]).toContain(timeOfDay());
  });
  test("an invalid date falls back to a neutral greeting rather than throwing", () => {
    expect(() => timeOfDay(new Date(NaN))).not.toThrow();
    expect(greeting(new Date(NaN))).toBe("Hello!");
  });
});

describe("greeting", () => {
  test("is 'Good {part of day}!'", () => {
    expect(greeting(at(8))).toBe("Good morning!");
    expect(greeting(at(13))).toBe("Good afternoon!");
    expect(greeting(at(20))).toBe("Good evening!");
  });
});
