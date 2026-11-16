import { useEffect, useState } from "react";
import { trafficResponseSchema, type TrafficResponse } from "@/lib/schemas";

export type StreamMode = "connecting" | "live" | "fallback";

const RETRY_MS = 15_000;

/**
 * Near-real-time traffic samples over the backend's SSE stream (ADR-0023). While the stream is not
 * open the caller polls instead, so a failed or unsupported stream never leaves the page empty.
 * The stream is closed while the tab is hidden or no firewall is selected.
 */
export function useTrafficStream(
  firewallId: string | null,
  active: boolean,
): { mode: StreamMode; sample: TrafficResponse | null } {
  const supported = typeof EventSource !== "undefined";
  const [mode, setMode] = useState<StreamMode>(supported ? "connecting" : "fallback");
  const [sample, setSample] = useState<TrafficResponse | null>(null);

  useEffect(() => {
    if (!supported || firewallId === null || !active) return;
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const open = () => {
      if (stopped) return;
      const es = new EventSource(`/api/v1/firewalls/${encodeURIComponent(firewallId)}/traffic/stream`);
      source = es;
      es.onopen = () => setMode("live");
      es.onmessage = (event: MessageEvent<string>) => {
        try {
          const parsed = trafficResponseSchema.safeParse(JSON.parse(event.data));
          if (parsed.success && parsed.data.firewall_id === firewallId) setSample(parsed.data);
        } catch {
          // a malformed event is ignored; the next one replaces it
        }
      };
      // The server ends a stream on purpose after its lifetime, a session check or a firewall edit.
      es.addEventListener("end", () => {
        es.close();
        open();
      });
      // The firewall could not be read three times in a row: poll so the page shows the real error.
      es.addEventListener("failure", () => {
        es.close();
        setMode("fallback");
        retry = setTimeout(open, RETRY_MS);
      });
      es.onerror = () => {
        es.close();
        setMode("fallback");
        retry = setTimeout(open, RETRY_MS);
      };
    };

    open();
    return () => {
      stopped = true;
      source?.close();
      clearTimeout(retry);
    };
  }, [supported, firewallId, active]);

  return { mode, sample };
}
