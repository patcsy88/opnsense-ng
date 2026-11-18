import { Loading } from "@/components/ui/loading";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ErrorState } from "@/components/error-state";
import { SelectField } from "@/components/ui/select-field";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { addSample, formatRate, type History } from "@/features/traffic/rates";
import { RATE_OPTIONS, rateSeconds, readRate, saveRate, type UpdateRate } from "@/features/traffic/update-rate";
import { useTrafficStream } from "@/features/traffic/use-traffic-stream";
import { useSelectedFirewall } from "@/features/firewall/selected-firewall";
import { api } from "@/lib/api";

const MIN_POLL_MS = 5_000;
// Firewall timestamps are not exact, so a sample just under the chosen gap still counts.
const GAP_TOLERANCE = 0.2;

export function TrafficPage() {
  const { options, firewalls, selected } = useSelectedFirewall();
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  const [history, setHistory] = useState<{ firewall: string | null; data: History }>({ firewall: null, data: {} });
  const origin = useRef<number | null>(null);
  const lastDrawn = useRef<number | null>(null);
  const [rate, setRate] = useState<UpdateRate>(readRate);
  const paused = rate === "paused";
  const every = rateSeconds(rate);
  useEffect(() => {
    origin.current = null;
    lastDrawn.current = null;
  }, [selected]);

  const changeRate = (next: UpdateRate) => {
    if (paused) {
      // The gap would otherwise be drawn as one long average, so start the series again.
      setHistory({ firewall: null, data: {} });
      origin.current = null;
    }
    lastDrawn.current = null;
    saveRate(next);
    setRate(next);
  };

  useEffect(() => {
    const onChange = () => setVisible(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", onChange);
    return () => document.removeEventListener("visibilitychange", onChange);
  }, []);

  const stream = useTrafficStream(selected, visible && !paused);
  const polling = stream.mode === "fallback";
  const q = useQuery({
    queryKey: ["firewalls", selected, "traffic"],
    queryFn: () => api.traffic(selected as string),
    enabled: selected !== null && visible && !paused && polling,
    refetchInterval: visible && !paused && polling ? Math.max(every * 1000, MIN_POLL_MS) : false,
    refetchIntervalInBackground: false,
  });

  const live = stream.sample?.firewall_id === selected ? stream.sample : null;
  const sample = polling ? (q.data ?? live ?? undefined) : (live ?? q.data);
  useEffect(() => {
    if (!sample || sample.time === null || paused) return;
    if (lastDrawn.current !== null && sample.time - lastDrawn.current < every - GAP_TOLERANCE) return;
    lastDrawn.current = sample.time;
    origin.current ??= sample.time;
    const base = origin.current;
    setHistory((prev) => {
      const same = prev.firewall === sample.firewall_id;
      return { firewall: sample.firewall_id, data: addSample(same ? prev.data : {}, sample, base) };
    });
  }, [sample, paused, every]);

  const series = history.firewall === selected ? Object.entries(history.data) : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Traffic</h1>
      </div>

      {options.isError && <ErrorState error={options.error} onRetry={() => void options.refetch()} />}
      {options.isSuccess && firewalls.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">No firewalls configured.</CardContent>
        </Card>
      )}
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}

      {selected && !q.isError && (
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="flex flex-wrap items-center gap-2">
                Interface traffic {sample && !sample.registry_verified && <UnverifiedBadge />}
              </CardTitle>
              <SelectField
                aria-label="Update rate"
                options={RATE_OPTIONS}
                value={rate}
                onValueChange={(v) => changeRate(v as UpdateRate)}
                size="sm"
                className="w-40"
              />
            </div>
            <CardDescription>
              Rates are worked out in your browser from the firewall's counters at the update rate you choose, for the
              last 5 minutes. Live updates arrive about every second while the stream is connected, and every 5
              seconds or slower if it is not. History is lost when you leave or reload this page, and updates pause
              while the tab is hidden.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {paused && series.length === 0 ? (
              <p className="text-sm text-muted-foreground">Paused. Choose an update rate to resume.</p>
            ) : sample === undefined ? (
              <Loading />
            ) : series.length === 0 ? (
              <p className="text-sm text-muted-foreground">No interface counters reported.</p>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Interface</TableHead>
                      <TableHead className="text-right">In</TableHead>
                      <TableHead className="text-right">Out</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {series.map(([id, s]) => {
                      const now = s.points.at(-1);
                      return (
                        <TableRow key={id}>
                          <TableCell>{s.label}</TableCell>
                          <TableCell className="text-right tabular-nums">{now ? formatRate(now.inBps) : "…"}</TableCell>
                          <TableCell className="text-right tabular-nums">{now ? formatRate(now.outBps) : "…"}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
                <div className="grid gap-4 lg:grid-cols-2">
                  {series.map(([id, s]) => (
                    <div key={id}>
                      <h3 className="mb-1 text-sm font-medium">{s.label}</h3>
                      {s.points.length < 2 ? (
                        <p className="text-xs text-muted-foreground">Collecting samples…</p>
                      ) : (
                        <div role="img" aria-label={`Traffic graph for ${s.label}`} className="h-48">
                          <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={s.points}>
                              <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.3} />
                              <XAxis dataKey="t" tickFormatter={(v: number) => `${v}s`} fontSize={11} />
                              <YAxis tickFormatter={(v: number) => formatRate(v)} width={78} fontSize={11} />
                              <Tooltip
                                formatter={(v) => formatRate(Number(v))}
                                labelFormatter={(v) => `${v}s`}
                                contentStyle={{
                                  background: "var(--overlay)",
                                  color: "var(--overlay-foreground)",
                                  border: "1px solid var(--border)",
                                  borderRadius: "var(--radius)",
                                  fontSize: 12,
                                  boxShadow: "var(--overlay-shadow, 0 4px 16px rgb(0 0 0 / 0.15))",
                                }}
                                labelStyle={{ color: "var(--muted)", marginBottom: 4 }}
                                itemStyle={{ color: "var(--overlay-foreground)" }}
                                cursor={{ stroke: "var(--muted)", strokeOpacity: 0.4 }}
                              />
                              <Legend />
                              <Line type="monotone" dataKey="inBps" name="In" stroke="#3b82f6" dot={false} isAnimationActive={false} />
                              <Line type="monotone" dataKey="outBps" name="Out" stroke="#f59e0b" dot={false} isAnimationActive={false} />
                            </LineChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
