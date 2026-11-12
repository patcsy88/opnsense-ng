import type { TrafficResponse } from "@/lib/schemas";

export const HISTORY_SECONDS = 300;

export interface RatePoint {
  /** Seconds since the first sample of this series, used as the chart x axis. */
  t: number;
  inBps: number;
  outBps: number;
}

export interface Series {
  label: string;
  points: RatePoint[];
  last: { inBytes: number; outBytes: number; time: number } | null;
}

export type History = Record<string, Series>;

/**
 * Add one poll to the history. Rates come from the difference to the previous sample of the same
 * interface. A counter that went down (reboot, interface reset) or a sample that is not newer restarts
 * that interface's series instead of drawing a spike.
 */
export function addSample(history: History, sample: TrafficResponse, origin: number): History {
  if (sample.time === null) return history;
  const time = sample.time;
  const next: History = {};
  for (const row of sample.interfaces) {
    const prev = history[row.interface];
    const label = row.name ?? row.interface;
    const last = { inBytes: row.in_bytes, outBytes: row.out_bytes, time };
    const base = prev?.last;
    const valid = base && time > base.time && row.in_bytes >= base.inBytes && row.out_bytes >= base.outBytes;
    if (!prev || !base || !valid) {
      next[row.interface] = { label, points: [], last };
      continue;
    }
    const seconds = time - base.time;
    const point: RatePoint = {
      t: Math.round(time - origin),
      inBps: (row.in_bytes - base.inBytes) / seconds,
      outBps: (row.out_bytes - base.outBytes) / seconds,
    };
    const points = [...prev.points, point].filter((p) => point.t - p.t <= HISTORY_SECONDS);
    next[row.interface] = { label, points, last };
  }
  return next;
}

export function formatRate(bytesPerSecond: number): string {
  const bits = bytesPerSecond * 8;
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
  let value = bits;
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i += 1;
  }
  return `${value >= 100 || i === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[i]}`;
}
