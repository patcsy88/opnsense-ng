import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { LogEntry, LogSummary } from "@/lib/schemas";

const LIVE_MS = 4_000;
const MAX_SHOWN = 200;
const ACTIONS = ["all", "block", "pass"] as const;

function endpoint(host: string | null, port: number | null) {
  if (!host) return "—";
  return port === null ? host : host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

function actionBadge(action: string | null) {
  if (!action) return <Badge>—</Badge>;
  return <Badge variant={action === "pass" ? "success" : action === "block" ? "critical" : "default"}>{action}</Badge>;
}

function matches(e: LogEntry, action: string, text: string): boolean {
  if (action !== "all" && e.action !== action) return false;
  if (!text) return true;
  const haystack = [e.source, e.destination, e.interface, e.protocol, e.rule, e.destination_port, e.source_port]
    .filter((v) => v !== null)
    .join(" ")
    .toLowerCase();
  return haystack.includes(text.toLowerCase());
}

function TopList({ title, items }: { title: string; items: { label: string; count: number }[] }) {
  return (
    <div>
      <h3 className="mb-1 text-sm font-medium">{title}</h3>
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">None</p>
      ) : (
        <ol className="space-y-0.5 text-xs">
          {items.map((i) => (
            <li key={i.label} className="flex justify-between gap-3">
              <span className="break-all font-mono">{i.label}</span>
              <span className="tabular-nums text-muted-foreground">{i.count}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function SummaryCard({ summary }: { summary: LogSummary }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Blocked traffic</CardTitle>
        <CardDescription>
          Over the {summary.records} newest log records
          {summary.oldest && summary.newest ? ` (${summary.oldest} to ${summary.newest})` : ""}: {summary.blocked}{" "}
          blocked, {summary.passed} passed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {summary.blocked === 0 ? (
          <p className="text-sm text-muted-foreground">No blocked traffic in these records.</p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <TopList title="Top blocked sources" items={summary.top_blocked_sources} />
            <TopList title="Top blocked destinations" items={summary.top_blocked_destinations} />
            <TopList title="Top blocked ports" items={summary.top_blocked_ports} />
            <TopList title="Blocked by interface" items={summary.blocked_by_interface} />
            <TopList title="Blocked by rule" items={summary.blocked_by_rule} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function LogsPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [action, setAction] = useState<(typeof ACTIONS)[number]>("all");
  const [text, setText] = useState("");
  const [liveFor, setLiveFor] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const [extra, setExtra] = useState<LogEntry[]>([]);
  const [liveError, setLiveError] = useState(false);
  const cursor = useRef<string | null>(null);
  const live = liveFor !== null && liveFor === selected;

  const q = useQuery({
    queryKey: ["firewalls", selected, "logs"],
    queryFn: async () => {
      const data = await api.firewallLogs(selected as string);
      // A full (re)load is the new baseline for live updates.
      cursor.current = data.cursor;
      setExtra([]);
      return data;
    },
    enabled: selected !== null,
    refetchInterval: live ? false : 30_000,
  });

  useEffect(() => {
    if (!live || selected === null) return;
    let stopped = false;
    let busy = false;
    const tick = async () => {
      if (busy || cursor.current === null) return;
      busy = true;
      try {
        const d = await api.firewallLogsNew(selected, cursor.current);
        if (stopped) return;
        cursor.current = d.cursor;
        setLiveError(false);
        if (d.entries.length > 0) setExtra((prev) => [...d.entries, ...prev].slice(0, MAX_SHOWN));
      } catch {
        if (!stopped) setLiveError(true);
      } finally {
        busy = false;
      }
    };
    void tick();
    const id = setInterval(() => void tick(), LIVE_MS);
    return () => {
      stopped = true;
      clearInterval(id);
    };
  }, [live, selected]);

  const all = useMemo(() => [...extra, ...(q.data?.entries ?? [])].slice(0, MAX_SHOWN), [extra, q.data]);
  const shown = useMemo(() => all.filter((e) => matches(e, action, text)), [all, action, text]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Logs</h1>
        {firewalls.length > 0 && (
          <label className="flex items-center gap-2 text-sm">
            Firewall
            <select
              className="h-9 rounded-md border border-border bg-card px-2"
              value={selected ?? ""}
              onChange={(e) => setChosen(e.target.value)}
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

      {q.data && <SummaryCard summary={q.data.summary} />}
      {selected && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              Firewall log {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              The most recent packet-filter entries, newest first. Refreshes every 30 seconds, or every few seconds with Live on. Filters apply to the
              entries loaded here only.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              {ACTIONS.map((a) => (
                <Button
                  key={a}
                  size="sm"
                  variant={action === a ? "default" : "outline"}
                  aria-pressed={action === a}
                  onClick={() => setAction(a)}
                >
                  {a === "all" ? "All" : a === "block" ? "Blocked" : "Passed"}
                </Button>
              ))}
              <Input
                aria-label="Filter entries"
                className="max-w-xs"
                placeholder="Filter by address, port, interface, rule…"
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <Button
                size="sm"
                variant={live ? "default" : "outline"}
                aria-pressed={live}
                disabled={q.data?.cursor == null}
                onClick={() => setLiveFor(live ? null : selected)}
              >
                {live ? "Live: on" : "Live"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => void q.refetch()} disabled={q.isFetching}>
                Refresh
              </Button>
            </div>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : all.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall returned no log entries.</p>
            ) : shown.length === 0 ? (
              <p className="text-sm text-muted-foreground">No loaded entries match the filter.</p>
            ) : (
              <>
                {live && liveError && (
                  <p role="alert" className="text-sm text-destructive">
                    Live updates failed; showing the last loaded entries. Retrying.
                  </p>
                )}
                {(q.data.truncated || all.length >= MAX_SHOWN) && (
                  <p className="text-sm text-muted-foreground">Only the newest {all.length} entries are shown.</p>
                )}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Interface</TableHead>
                      <TableHead>Dir</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Rule</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {shown.map((e, n) => (
                      <TableRow key={`${e.time ?? "?"}-${n}`}>
                        <TableCell className="whitespace-nowrap text-xs">{e.time ?? "—"}</TableCell>
                        <TableCell>{actionBadge(e.action)}</TableCell>
                        <TableCell>{e.interface ?? "—"}</TableCell>
                        <TableCell>{e.direction ?? "—"}</TableCell>
                        <TableCell>{e.protocol ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(e.source, e.source_port)}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(e.destination, e.destination_port)}</TableCell>
                        <TableCell className="text-xs">{e.rule ?? "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
