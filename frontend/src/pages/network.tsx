import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge, UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { InterfaceInfo } from "@/lib/schemas";

function statusBadge(i: InterfaceInfo) {
  if (i.status === "up") return <StatusBadge level="healthy" label="Up" />;
  if (!i.status) return <Badge>Unknown</Badge>;
  return <StatusBadge level={i.enabled === false ? "warning" : "critical"} label={i.status} />;
}

export function NetworkPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "interfaces"],
    queryFn: () => api.interfaces(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Network</h1>
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
              Interfaces {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>Read-only status reported by the firewall</CardDescription>
          </CardHeader>
          <CardContent>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.interfaces.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall reported no interfaces.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Interface</TableHead>
                    <TableHead>Device</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>IPv4</TableHead>
                    <TableHead>IPv6</TableHead>
                    <TableHead>Gateway</TableHead>
                    <TableHead>VLAN</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {q.data.interfaces.map((i, n) => (
                    <TableRow key={`${i.device ?? "?"}-${n}`}>
                      <TableCell className="font-medium">{i.description ?? i.identifier ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{i.device ?? "—"}</TableCell>
                      <TableCell>{statusBadge(i)}</TableCell>
                      <TableCell className="font-mono text-xs">{i.ipv4.join(", ") || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{i.ipv6.join(", ") || "—"}</TableCell>
                      <TableCell>{i.gateways.join(", ") || "—"}</TableCell>
                      <TableCell>{i.vlan_tag ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
