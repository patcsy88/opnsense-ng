import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api";
import type { WireguardRecord } from "@/lib/schemas";

function size(value: number | null): string {
  if (value === null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = value;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${i === 0 ? n : n.toFixed(1)} ${units[i]}`;
}

function handshake(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function statusVariant(status: string | null) {
  if (status === "online" || status === "up") return "success" as const;
  if (status === "stale") return "warning" as const;
  return "critical" as const;
}

export function VpnPage() {
  const options = useQuery({
    queryKey: ["firewalls", "options"],
    queryFn: api.listFirewallOptions,
  });
  const [chosen, setChosen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "wireguard"],
    queryFn: () => api.wireguard(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  const groups = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const byInterface = new Map<
      string,
      { head: WireguardRecord | null; peers: WireguardRecord[] }
    >();
    for (const r of q.data?.records ?? []) {
      const entry = byInterface.get(r.interface) ?? { head: null, peers: [] };
      if (r.type === "interface") entry.head = r;
      else entry.peers.push(r);
      byInterface.set(r.interface, entry);
    }
    return [...byInterface.entries()].map(([name, g]) => ({
      name,
      head: g.head,
      peers: needle
        ? g.peers.filter((p) =>
            [p.name, p.endpoint, p.status, ...p.allowed_ips]
              .filter((v) => v !== null)
              .join(" ")
              .toLowerCase()
              .includes(needle),
          )
        : g.peers,
    }));
  }, [q.data, text]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">VPN</h1>
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

      {options.isError && (
        <ErrorState
          error={options.error}
          onRetry={() => void options.refetch()}
        />
      )}
      {options.isSuccess && firewalls.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">
            No firewalls configured.
          </CardContent>
        </Card>
      )}
      {q.isError && (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      )}

      {selected && !q.isError && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              WireGuard{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              Read-only status. Keys are not shown, and tunnels and peers cannot
              be changed here. Refreshes every 30 seconds.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading…
              </p>
            ) : (
              <>
                <Input
                  aria-label="Filter peers"
                  placeholder="Filter by peer, endpoint, address or status"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className="max-w-sm"
                />
                {groups.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No WireGuard tunnels found.
                  </p>
                )}
                {groups.map((g) => (
                  <section
                    key={g.name}
                    className="space-y-2"
                    aria-label={`Tunnel ${g.name}`}
                  >
                    <h2 className="flex flex-wrap items-center gap-2 text-lg font-medium">
                      {g.head?.tunnel_name ?? g.name}
                      <span className="font-mono text-xs text-muted-foreground">
                        {g.name}
                      </span>
                      {g.head?.status && (
                        <Badge variant={statusVariant(g.head.status)}>
                          {g.head.status}
                        </Badge>
                      )}
                      {g.head?.listen_port != null && (
                        <span className="text-xs text-muted-foreground">
                          port {g.head.listen_port}
                        </span>
                      )}
                    </h2>
                    {g.peers.length === 0 ? (
                      <p className="text-sm text-muted-foreground">
                        No peers match.
                      </p>
                    ) : (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Peer</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Endpoint</TableHead>
                            <TableHead>Allowed IPs</TableHead>
                            <TableHead>Last handshake</TableHead>
                            <TableHead>Received</TableHead>
                            <TableHead>Sent</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {g.peers.map((p, i) => (
                            <TableRow key={`${g.name}-${i}`}>
                              <TableCell>{p.name ?? "—"}</TableCell>
                              <TableCell>
                                <Badge variant={statusVariant(p.status)}>
                                  {p.status ?? "unknown"}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-xs sm:text-sm">
                                {p.endpoint ?? "—"}
                              </TableCell>
                              <TableCell className="font-mono text-xs sm:text-sm">
                                {p.allowed_ips.length
                                  ? p.allowed_ips.join(", ")
                                  : "—"}
                              </TableCell>
                              <TableCell>
                                {handshake(p.latest_handshake)}
                              </TableCell>
                              <TableCell>{size(p.rx_bytes)}</TableCell>
                              <TableCell>{size(p.tx_bytes)}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </section>
                ))}
                {q.data?.truncated && (
                  <p className="text-xs text-muted-foreground">
                    The list was cut off at 500 rows.
                  </p>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
