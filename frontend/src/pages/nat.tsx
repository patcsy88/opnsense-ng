import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { NatRule } from "@/lib/schemas";

type Kind = "port-forwards" | "outbound";

type KindInfo = { id: Kind; label: string; description: string; excludedLabel: string };

const KINDS: [KindInfo, KindInfo] = [
  {
    id: "port-forwards",
    label: "Port forwards",
    description: "Destination NAT: traffic arriving at the firewall that is redirected to an internal address.",
    excludedLabel: "No redirect",
  },
  {
    id: "outbound",
    label: "Outbound",
    description: "Source NAT: how internal addresses are translated when leaving through an interface.",
    excludedLabel: "Do not NAT",
  },
];

function endpoint(host: string | null, port: string | null) {
  if (!host && !port) return "—";
  return `${host ?? "any"}${port ? `:${port}` : ""}`;
}

function NatTable({ rules, kind }: { rules: NatRule[]; kind: KindInfo }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>#</TableHead>
          <TableHead>Interface</TableHead>
          <TableHead>Protocol</TableHead>
          <TableHead>Source</TableHead>
          <TableHead>Destination</TableHead>
          <TableHead>{kind.id === "port-forwards" ? "Redirect to" : "Translate to"}</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Enabled</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((r, n) => (
          <TableRow key={`${r.uuid ?? "?"}-${n}`}>
            <TableCell>{r.sequence ?? "—"}</TableCell>
            <TableCell>{r.interface ?? "—"}</TableCell>
            <TableCell>{[r.ip_protocol, r.protocol].filter(Boolean).join(" ") || "—"}</TableCell>
            <TableCell className="font-mono text-xs">{endpoint(r.source, r.source_port)}</TableCell>
            <TableCell className="font-mono text-xs">{endpoint(r.destination, r.destination_port)}</TableCell>
            <TableCell className="font-mono text-xs">
              {r.excluded ? <Badge>{kind.excludedLabel}</Badge> : endpoint(r.target, r.target_port)}
            </TableCell>
            <TableCell>
              {r.description ?? "—"}
              {r.automatic && <span className="ml-1 text-xs text-muted-foreground">(automatic)</span>}
            </TableCell>
            <TableCell>{r.enabled === null ? "—" : r.enabled ? "Yes" : "No"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function NatPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [kindId, setKindId] = useState<Kind>("port-forwards");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;
  const kind = KINDS.find((k) => k.id === kindId) ?? KINDS[0];

  const q = useQuery({
    queryKey: ["firewalls", selected, "nat", kindId],
    queryFn: () => api.natRules(selected as string, kindId),
    enabled: selected !== null,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">NAT</h1>
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
              {kind.label} {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>{kind.description} Read-only.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex gap-2" role="group" aria-label="NAT type">
              {KINDS.map((k) => (
                <Button
                  key={k.id}
                  size="sm"
                  variant={kindId === k.id ? "default" : "outline"}
                  aria-pressed={kindId === k.id}
                  onClick={() => setKindId(k.id)}
                >
                  {k.label}
                </Button>
              ))}
            </div>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall reported no {kind.label.toLowerCase()}.</p>
            ) : (
              <>
                {q.data.truncated && <p className="text-sm text-muted-foreground">Only the first rules are shown.</p>}
                <NatTable rules={q.data.rules} kind={kind} />
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
