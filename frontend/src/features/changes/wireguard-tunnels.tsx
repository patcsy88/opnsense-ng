import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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

export function WireguardTunnels({ firewallId }: { firewallId: string }) {
  const q = useQuery({
    queryKey: ["firewalls", firewallId, "wireguard-tunnels"],
    queryFn: () => api.wireguardTunnels(firewallId),
  });
  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Tunnels {q.data && !q.data.registry_verified && <UnverifiedBadge />}
        </CardTitle>
        <CardDescription>
          WireGuard tunnels configured on the firewall. Private keys are never
          read or shown.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {q.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">
            Loading…
          </p>
        ) : q.data.tunnels.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            The firewall has no tunnels.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead>Public key</TableHead>
                  <TableHead>Peers</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {q.data.tunnels.map((t) => (
                  <TableRow key={t.uuid ?? String(t.name)}>
                    <TableCell>{t.name ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {t.tunneladdress.length
                        ? t.tunneladdress.join(", ")
                        : "—"}
                    </TableCell>
                    <TableCell>{t.port ?? "—"}</TableCell>
                    <TableCell className="max-w-[14rem] break-all font-mono text-xs">
                      {t.pubkey ?? "—"}
                    </TableCell>
                    <TableCell>{t.peers.length}</TableCell>
                    <TableCell>
                      {t.enabled ? "Enabled" : <Badge>Disabled</Badge>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
