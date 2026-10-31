export type MascotPose = "hero" | "avatar" | "rest" | "puzzled";

// Fixed lookup: the class is chosen from this table, never from the prop's raw value.
const POSES: Record<MascotPose, string> = {
  hero: "mascot--hero",
  avatar: "mascot--avatar",
  rest: "mascot--rest",
  puzzled: "mascot--puzzled",
};

/**
 * The watchdog. Deliberately a CSS background on an aria-hidden span and never an <img>: the art
 * is decoration, and no <img> means a hostile report can never be confused with app art. The
 * stylesheet puts a soft gradient disc behind each pose, so a missing PNG still renders cleanly.
 */
export function Mascot({
  pose,
  size,
  float = false,
}: {
  pose: MascotPose;
  size: number;
  float?: boolean;
}) {
  const cls = Object.hasOwn(POSES, pose) ? POSES[pose] : POSES.rest;
  return (
    <span
      className={`mascot ${cls}${float ? " mascot--float" : ""}`}
      aria-hidden="true"
      style={{ width: size, height: size }}
    />
  );
}
