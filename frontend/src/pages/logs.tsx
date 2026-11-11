import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { LogEntry } from "@/lib/schemas";

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

export function LogsPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [action, setAction] = useState<(typeof ACTIONS)[number]>("all");
  const [text, setText] = useState("");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "logs"],
    queryFn: () => api.firewallLogs(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  const shown = useMemo(() => (q.data?.entries ?? []).filter((e) => matches(e, action, text)), [q.data, action, text]);

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

      {selected && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              Firewall log {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              The most recent packet-filter entries, newest first. Refreshes every 30 seconds. Filters apply to the
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
              <Button size="sm" variant="ghost" onClick={() => void q.refetch()} disabled={q.isFetching}>
                Refresh
              </Button>
            </div>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.entries.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall returned no log entries.</p>
            ) : shown.length === 0 ? (
              <p className="text-sm text-muted-foreground">No loaded entries match the filter.</p>
            ) : (
              <>
                {q.data.truncated && (
                  <p className="text-sm text-muted-foreground">Only the newest {q.data.entries.length} entries are shown.</p>
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
