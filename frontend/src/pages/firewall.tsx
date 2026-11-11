import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { RuleInfo } from "@/lib/schemas";

function actionBadge(r: RuleInfo) {
  if (!r.action) return <Badge>—</Badge>;
  return <Badge variant={r.action === "pass" ? "success" : "critical"}>{r.action}</Badge>;
}

function endpoint(net: string | null, port: string | null) {
  return [net ?? "any", port].filter(Boolean).join(":");
}

export function FirewallPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "rules"],
    queryFn: () => api.firewallRules(selected as string),
    enabled: selected !== null,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Firewall</h1>
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
              Rules {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>Read-only list of filter rules</CardDescription>
          </CardHeader>
          <CardContent>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall reported no rules.</p>
            ) : (
              <>
                {q.data.truncated && (
                  <p className="mb-2 text-sm text-muted-foreground">Only the first rules are shown.</p>
                )}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>#</TableHead>
                      <TableHead>Interface</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Direction</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Enabled</TableHead>
                      <TableHead>Log</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {q.data.rules.map((r, n) => (
                      <TableRow key={`${r.uuid ?? "?"}-${n}`}>
                        <TableCell>{r.sequence ?? "—"}</TableCell>
                        <TableCell>{r.interface ?? "—"}</TableCell>
                        <TableCell>{actionBadge(r)}</TableCell>
                        <TableCell>{r.direction ?? "—"}</TableCell>
                        <TableCell>{[r.ip_protocol, r.protocol].filter(Boolean).join(" ") || "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(r.source, r.source_port)}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(r.destination, r.destination_port)}</TableCell>
                        <TableCell>{r.description ?? "—"}</TableCell>
                        <TableCell>{r.enabled === null ? "—" : r.enabled ? "Yes" : "No"}</TableCell>
                        <TableCell>{r.log === null ? "—" : r.log ? "Yes" : "No"}</TableCell>
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
