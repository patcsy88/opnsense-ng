import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge, UnverifiedBadge } from "@/components/ui/status-badge";
import { ErrorState } from "@/components/error-state";
import { api } from "@/lib/api";
import type { SystemStatus } from "@/lib/schemas";
import { useAuth } from "@/features/auth/auth";
import { connectivityLevel, systemLevel } from "./health";

function Row({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex justify-between gap-4 py-1 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium">{value || "—"}</dd>
    </div>
  );
}

function formatMemory(s: SystemStatus): string | null {
  if (s.memory_used_bytes === null || s.memory_total_bytes === null || s.memory_used_percent === null) {
    return null;
  }
  const mb = (n: number) => `${Math.round(n / 1024 / 1024)} MB`;
  return `${mb(s.memory_used_bytes)} of ${mb(s.memory_total_bytes)} (${s.memory_used_percent}%)`;
}

export function ConnectivityCard({ firewallId, intervalMs }: { firewallId: string; intervalMs: number | false }) {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const q = useQuery({
    queryKey: ["firewalls", firewallId, "connectivity"],
    queryFn: () => api.connectivity(firewallId),
    refetchInterval: intervalMs,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connectivity</CardTitle>
        <CardDescription>Backend to firewall</CardDescription>
      </CardHeader>
      <CardContent>
        {q.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">Checking…</p>
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge
                level={connectivityLevel(q.data)}
                label={q.data.ok ? "Reachable" : "Unreachable"}
              />
              {!q.data.registry_verified && <UnverifiedBadge />}
            </div>
            {admin ? (
              <dl>
                <Row label="Status" value={q.data.status} />
                <Row label="Message" value={q.data.message} />
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">{q.data.message}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function SystemStatusCard({ firewallId, intervalMs }: { firewallId: string; intervalMs: number | false }) {
  const q = useQuery({
    queryKey: ["firewalls", firewallId, "system-status"],
    queryFn: () => api.systemStatus(firewallId),
    refetchInterval: intervalMs,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>System status</CardTitle>
        <CardDescription>Reported by the firewall</CardDescription>
      </CardHeader>
      <CardContent>
        {q.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">Loading…</p>
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge level={systemLevel(q.data.status)} />
              {!q.data.registry_verified && <UnverifiedBadge />}
            </div>
            <dl>
              <Row label="Hostname" value={q.data.status.hostname} />
              <Row label="Version" value={q.data.status.versions.join(", ")} />
              <Row label="Uptime" value={q.data.status.uptime} />
              <Row label="Updates" value={q.data.status.updates} />
              <Row label="Firewall time" value={q.data.status.server_time} />
              <Row label="Load average" value={q.data.status.load_average} />
              <Row label="CPU usage" value={q.data.status.cpu_used_percent === null ? null : `${q.data.status.cpu_used_percent}%`} />
              <Row label="Memory" value={formatMemory(q.data.status)} />
            </dl>
            <p className="text-xs text-muted-foreground">
              Disk usage is not provided by the backend yet.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
