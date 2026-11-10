import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/features/auth/auth";
import { ConnectivityCard, SystemStatusCard } from "@/features/dashboard/firewall-cards";
import { api } from "@/lib/api";

export const POLL_OPTIONS = [
  { label: "5 s", ms: 5_000 },
  { label: "15 s", ms: 15_000 },
  { label: "30 s", ms: 30_000 },
  { label: "60 s", ms: 60_000 },
  { label: "Off", ms: 0 },
] as const;

export function DashboardPage() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const [params, setParams] = useSearchParams();
  const [pollMs, setPollMs] = useState<number>(30_000); // in memory only
  const fwParam = params.get("fw");

  // Only admins may list firewalls (backend GET /firewalls is admin-only).
  const list = useQuery({
    queryKey: ["firewalls"],
    queryFn: api.listFirewalls,
    enabled: admin,
  });

  const firewalls = useMemo(() => list.data ?? [], [list.data]);
  const selected = fwParam ?? firewalls[0]?.id ?? null;

  useEffect(() => {
    if (!fwParam && firewalls[0]) setParams({ fw: firewalls[0].id }, { replace: true });
  }, [fwParam, firewalls, setParams]);

  const interval = pollMs > 0 ? pollMs : false;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          {admin && firewalls.length > 0 && (
            <label className="flex items-center gap-2">
              Firewall
              <select
                className="h-9 rounded-md border border-border bg-card px-2"
                value={selected ?? ""}
                onChange={(e) => setParams({ fw: e.target.value })}
              >
                {firewalls.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="flex items-center gap-2">
            Refresh
            <select
              className="h-9 rounded-md border border-border bg-card px-2"
              value={pollMs}
              onChange={(e) => setPollMs(Number(e.target.value))}
            >
              {POLL_OPTIONS.map((o) => (
                <option key={o.ms} value={o.ms}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {admin && list.isError && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}

      {admin && list.isSuccess && firewalls.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">
            No firewalls configured.{" "}
            <Link className="text-primary underline" to="/administration/firewalls">
              Add a firewall connection
            </Link>
            .
          </CardContent>
        </Card>
      )}

      {!admin && !selected && (
        <Card>
          <CardContent className="pt-4 text-sm text-muted-foreground">
            The firewall list is only available to administrators. Open a dashboard link that includes a
            firewall (<code>?fw=…</code>) provided by your administrator.
          </CardContent>
        </Card>
      )}

      {selected && (
        <div className="grid gap-4 lg:grid-cols-2">
          <ConnectivityCard firewallId={selected} intervalMs={interval} />
          <SystemStatusCard firewallId={selected} intervalMs={interval} />
        </div>
      )}
    </div>
  );
}
