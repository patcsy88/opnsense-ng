import { describe, expect, it } from "vitest";
import type { TrafficResponse } from "@/lib/schemas";
import { addSample, formatRate, HISTORY_SECONDS, type History } from "./rates";

const sample = (time: number | null, inBytes: number, outBytes = 0, id = "wan"): TrafficResponse => ({
  firewall_id: "33333333-3333-4333-8333-333333333333",
  time,
  interfaces: [{ interface: id, name: "WAN", in_bytes: inBytes, out_bytes: outBytes, in_packets: 0, out_packets: 0 }],
  registry_verified: true,
});

describe("addSample", () => {
  it("has no rate for the first sample, then computes bytes per second", () => {
    let h: History = addSample({}, sample(100, 1000), 100);
    expect(h.wan?.points).toHaveLength(0);
    h = addSample(h, sample(105, 6000, 500), 100);
    expect(h.wan?.points).toEqual([{ t: 5, inBps: 1000, outBps: 100 }]);
    expect(h.wan?.label).toBe("WAN");
  });

  it("restarts the series when a counter goes down instead of drawing a spike", () => {
    let h = addSample({}, sample(100, 9000), 100);
    h = addSample(h, sample(105, 14000), 100);
    expect(h.wan?.points).toHaveLength(1);
    h = addSample(h, sample(110, 50), 100);
    expect(h.wan?.points).toHaveLength(0);
    h = addSample(h, sample(115, 550), 100);
    expect(h.wan?.points[0]?.inBps).toBe(100);
  });

  it("ignores a sample that is not newer and a sample without a time", () => {
    let h = addSample({}, sample(100, 1000), 100);
    expect(addSample(h, sample(null, 5000), 100)).toBe(h);
    h = addSample(h, sample(100, 2000), 100);
    expect(h.wan?.points).toHaveLength(0);
  });

  it("keeps only the last five minutes and drops interfaces that disappear", () => {
    let h: History = {};
    for (let n = 0; n <= 100; n += 1) h = addSample(h, sample(100 + n * 10, n * 100), 100);
    const points = h.wan?.points ?? [];
    expect(points.length).toBeLessThanOrEqual(HISTORY_SECONDS / 10 + 1);
    expect((points.at(-1)?.t ?? 0) - (points[0]?.t ?? 0)).toBeLessThanOrEqual(HISTORY_SECONDS);
    expect(addSample(h, sample(2000, 1, 0, "lan"), 100).wan).toBeUndefined();
  });
});

describe("formatRate", () => {
  it("shows bits per second with sensible units", () => {
    expect(formatRate(0)).toBe("0 bit/s");
    expect(formatRate(125)).toBe("1.0 kbit/s");
    expect(formatRate(1_250_000)).toBe("10.0 Mbit/s");
    expect(formatRate(125_000_000)).toBe("1.0 Gbit/s");
  });
});
