import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Button } from "@/components/ui/button";
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

type Section = "leases" | "reservations" | "subnets";

function when(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function Panel({
  title,
  description,
  verified,
  loading,
  error,
  onRetry,
  empty,
  children,
}: {
  title: string;
  description: string;
  verified: boolean | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  empty: boolean;
  children: React.ReactNode;
}) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          {title} {verified === false && <UnverifiedBadge />}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p role="status" className="text-sm text-muted-foreground">
            Loading…
          </p>
        ) : empty ? (
          <p className="text-sm text-muted-foreground">Nothing to show.</p>
        ) : (
          <Table>{children}</Table>
        )}
      </CardContent>
    </Card>
  );
}

function Leases({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["firewalls", id, "kea-leases"],
    queryFn: () => api.keaLeases(id),
    refetchInterval: 30_000,
  });
  return (
    <Panel
      title="Kea leases"
      description="Read-only. MAC addresses are not shown."
      verified={q.data?.registry_verified}
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      empty={q.data?.leases.length === 0}
    >
      <TableHeader>
        <TableRow>
          <TableHead>Address</TableHead>
          <TableHead>Hostname</TableHead>
          <TableHead>Interface</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Expires</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {q.data?.leases.map((l, i) => (
          <TableRow key={`${l.address}-${i}`}>
            <TableCell className="font-mono text-xs sm:text-sm">
              {l.address}
            </TableCell>
            <TableCell>{l.hostname ?? "—"}</TableCell>
            <TableCell>{l.interface ?? "—"}</TableCell>
            <TableCell>{l.state ?? "—"}</TableCell>
            <TableCell>{when(l.expires)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Panel>
  );
}

function Reservations({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["firewalls", id, "kea-reservations"],
    queryFn: () => api.keaReservations(id),
  });
  return (
    <Panel
      title="Kea reservations"
      description="Read-only. Visible to administrators and network administrators."
      verified={q.data?.registry_verified}
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      empty={q.data?.reservations.length === 0}
    >
      <TableHeader>
        <TableRow>
          <TableHead>IP address</TableHead>
          <TableHead>Subnet</TableHead>
          <TableHead>MAC address</TableHead>
          <TableHead>Hostname</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {q.data?.reservations.map((r) => (
          <TableRow key={r.uuid}>
            <TableCell className="font-mono text-xs sm:text-sm">
              {r.ip_address}
            </TableCell>
            <TableCell className="font-mono text-xs sm:text-sm">
              {r.subnet ?? "—"}
            </TableCell>
            <TableCell className="font-mono text-xs sm:text-sm">
              {r.hw_address ?? "—"}
            </TableCell>
            <TableCell>{r.hostname ?? "—"}</TableCell>
            <TableCell>{r.description ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Panel>
  );
}

function Subnets({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["firewalls", id, "kea-subnets"],
    queryFn: () => api.keaSubnets(id),
  });
  return (
    <Panel
      title="Kea subnets"
      description="Read-only."
      verified={q.data?.registry_verified}
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      empty={q.data?.subnets.length === 0}
    >
      <TableHeader>
        <TableRow>
          <TableHead>Subnet</TableHead>
          <TableHead>Pools</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {q.data?.subnets.map((s) => (
          <TableRow key={s.uuid}>
            <TableCell className="font-mono text-xs sm:text-sm">
              {s.subnet}
            </TableCell>
            <TableCell className="font-mono text-xs sm:text-sm">
              {s.pools.length ? s.pools.join(", ") : "—"}
            </TableCell>
            <TableCell>{s.description ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Panel>
  );
}

export function KeaTab({
  firewallId,
  canManage,
}: {
  firewallId: string;
  canManage: boolean;
}) {
  const [section, setSection] = useState<Section>("leases");
  const sections: [Section, string][] = [
    ["leases", "Leases"],
    ...(canManage
      ? ([["reservations", "Reservations"]] as [Section, string][])
      : []),
    ["subnets", "Subnets"],
  ];
  const shown = sections.some(([s]) => s === section) ? section : "leases";
  return (
    <>
      <div role="tablist" aria-label="Kea section" className="flex gap-2">
        {sections.map(([id, text]) => (
          <Button
            key={id}
            role="tab"
            aria-selected={shown === id}
            size="sm"
            variant={shown === id ? "default" : "outline"}
            onClick={() => setSection(id)}
          >
            {text}
          </Button>
        ))}
      </div>
      {shown === "leases" && <Leases id={firewallId} />}
      {shown === "reservations" && <Reservations id={firewallId} />}
      {shown === "subnets" && <Subnets id={firewallId} />}
    </>
  );
}
