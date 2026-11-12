import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ErrorState } from "@/components/error-state";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { addSample, formatRate, type History } from "@/features/traffic/rates";
import { api } from "@/lib/api";

const POLL_MS = 5_000;

export function TrafficPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  const [history, setHistory] = useState<{ firewall: string | null; data: History }>({ firewall: null, data: {} });
  const origin = useRef<number | null>(null);

  useEffect(() => {
    const onChange = () => setVisible(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", onChange);
    return () => document.removeEventListener("visibilitychange", onChange);
  }, []);

  const q = useQuery({
    queryKey: ["firewalls", selected, "traffic"],
    queryFn: () => api.traffic(selected as string),
    enabled: selected !== null && visible,
    refetchInterval: visible ? POLL_MS : false,
    refetchIntervalInBackground: false,
  });

  const sample = q.data;
  useEffect(() => {
    if (!sample || sample.time === null) return;
    origin.current ??= sample.time;
    const base = origin.current;
    setHistory((prev) => {
      const same = prev.firewall === sample.firewall_id;
      return { firewall: sample.firewall_id, data: addSample(same ? prev.data : {}, sample, base) };
    });
  }, [sample]);

  const series = history.firewall === selected ? Object.entries(history.data) : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Traffic</h1>
        {firewalls.length > 0 && (
          <label className="flex items-center gap-2 text-sm">
            Firewall
            <select
              className="h-9 rounded-md border border-border bg-card px-2"
              value={selected ?? ""}
              onChange={(e) => {
                origin.current = null;
                setChosen(e.target.value);
              }}
            >
              {firewalls.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
          </label>
        )}
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
            <CardTitle className="flex flex-wrap items-center gap-2">
              Interface traffic {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              Rates are worked out in your browser from the firewall's counters, every 5 seconds, for the last 5
              minutes. History is lost when you leave or reload this page, and polling pauses while the tab is hidden.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
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
                              <Tooltip formatter={(v) => formatRate(Number(v))} labelFormatter={(v) => `${v}s`} />
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
