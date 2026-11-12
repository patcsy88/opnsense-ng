import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";

export function ServicesPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "services"],
    queryFn: () => api.services(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const rows = q.data?.services ?? [];
    return needle
      ? rows.filter((s) => `${s.name} ${s.description ?? ""}`.toLowerCase().includes(needle))
      : rows;
  }, [q.data, text]);
  const stopped = (q.data?.services ?? []).filter((s) => !s.running).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Services</h1>
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
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}

      {selected && !q.isError && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              Service status {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              Read-only. Starting, stopping and restarting services is not available here. Refreshes every 30
              seconds.
              {q.data && ` ${q.data.services.length} services, ${stopped} not running.`}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : (
              <>
                <Input
                  aria-label="Filter services"
                  placeholder="Filter by name or description"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className="max-w-xs"
                />
                {shown.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No services match.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {shown.map((s) => (
                        <TableRow key={s.id}>
                          <TableCell className="font-mono text-xs sm:text-sm">{s.id}</TableCell>
                          <TableCell>{s.description ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant={s.running ? "success" : "critical"}>
                              {s.running ? "Running" : "Stopped"}
                            </Badge>
                            {s.locked && <span className="ml-2 text-xs text-muted-foreground">locked</span>}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {q.data?.truncated && (
                  <p className="text-xs text-muted-foreground">The list was cut off at 500 services.</p>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
