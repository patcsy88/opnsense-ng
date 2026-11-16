export type UpdateRate = "1" | "2" | "5" | "10" | "paused";

export const RATE_KEY = "traffic-update-rate";

export const RATE_OPTIONS: readonly { value: UpdateRate; label: string }[] = [
  { value: "1", label: "Live (1 s)" },
  { value: "2", label: "Every 2 s" },
  { value: "5", label: "Every 5 s" },
  { value: "10", label: "Every 10 s" },
  { value: "paused", label: "Paused" },
];

export function readRate(): UpdateRate {
  try {
    const v = localStorage.getItem(RATE_KEY);
    return RATE_OPTIONS.some((o) => o.value === v) ? (v as UpdateRate) : "1";
  } catch {
    return "1";
  }
}

export function saveRate(rate: UpdateRate): void {
  try {
    localStorage.setItem(RATE_KEY, rate);
  } catch {
    // a blocked store only means the choice is not remembered
  }
}

export function rateSeconds(rate: UpdateRate): number {
  return rate === "paused" ? 0 : Number(rate);
}
