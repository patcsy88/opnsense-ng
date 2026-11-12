import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";

function expiry(value: string | null): string {
  if (!value) return "No expiry";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function DhcpPage() {
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "dhcp-leases"],
    queryFn: () => api.dhcpLeases(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const rows = q.data?.leases ?? [];
    return needle
      ? rows.filter((l) =>
          [l.address, l.hostname, l.interface, l.vendor, l.lease_type]
            .filter((v) => v !== null)
            .join(" ")
            .toLowerCase()
            .includes(needle),
        )
      : rows;
  }, [q.data, text]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">DHCP</h1>
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
              DHCP leases {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              Read-only list of Dnsmasq leases. MAC addresses are not shown. Refreshes every 30 seconds.
              {q.data && ` ${q.data.leases.length} leases.`}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : (
              <>
                <Input
                  aria-label="Filter leases"
                  placeholder="Filter by address, hostname, interface or vendor"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className="max-w-sm"
                />
                {shown.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No leases match.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Address</TableHead>
                        <TableHead>Hostname</TableHead>
                        <TableHead>Interface</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Vendor</TableHead>
                        <TableHead>Expires</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {shown.map((l, i) => (
                        <TableRow key={`${l.address}-${i}`}>
                          <TableCell className="font-mono text-xs sm:text-sm">{l.address}</TableCell>
                          <TableCell>{l.hostname ?? "—"}</TableCell>
                          <TableCell>{l.interface ?? "—"}</TableCell>
                          <TableCell>
                            {l.lease_type ? (
                              <Badge variant={l.lease_type === "static" ? "success" : "default"}>{l.lease_type}</Badge>
                            ) : (
                              "—"
                            )}
                          </TableCell>
                          <TableCell>{l.vendor ?? "—"}</TableCell>
                          <TableCell>{expiry(l.expires)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {q.data?.truncated && (
                  <p className="text-xs text-muted-foreground">The list was cut off at 1000 leases.</p>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
