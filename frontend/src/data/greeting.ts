export type TimeOfDay = "morning" | "afternoon" | "evening";

/** Morning 05:00-11:59, afternoon 12:00-17:59, evening 18:00-04:59 (local time). */
export function timeOfDay(now: Date = new Date()): TimeOfDay | null {
  const h = now.getHours();
  if (Number.isNaN(h)) return null;
  if (h >= 5 && h < 12) return "morning";
  if (h >= 12 && h < 18) return "afternoon";
  return "evening";
}

/** "Good morning!" etc. An unreadable clock gets a neutral "Hello!". */
export function greeting(now: Date = new Date()): string {
  const part = timeOfDay(now);
  return part ? `Good ${part}!` : "Hello!";
}
