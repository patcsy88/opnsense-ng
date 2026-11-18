import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loading } from "@/components/ui/loading";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuth } from "@/features/auth/auth";
import { useSelectedFirewall } from "@/features/firewall/selected-firewall";
import { api } from "@/lib/api";
import type { OverviewEntry } from "@/lib/schemas";

export const POLL_OPTIONS = [
  { label: "30 s", ms: 30_000 },
  { label: "60 s", ms: 60_000 },
  { label: "Off", ms: 0 },
] as const;

const pct = (v: number | null) => (v === null ? "–" : `${v.toFixed(0)}%`);

function Meter({ label, value }: { label: string; value: number | null }) {
  const width = value === null ? 0 : Math.min(100, Math.max(0, value));
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium">{pct(value)}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-default" aria-hidden>
        <div className="h-full rounded-full bg-primary" style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex justify-between gap-4 py-0.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium">{value ?? "–"}</dd>
    </div>
  );
}

function FirewallCard({
  entry,
  selected,
  admin,
  onSelect,
}: {
  entry: OverviewEntry;
  selected: boolean;
  admin: boolean;
  onSelect: () => void;
}) {
  return (
    <Card className={selected ? "ring-2 ring-primary" : undefined}>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle>
            <button
              type="button"
              className="text-left hover:underline focus-visible:underline"
              aria-pressed={selected}
              onClick={onSelect}
            >
              {entry.name}
            </button>
          </CardTitle>
          <StatusBadge
            level={entry.reachable ? "healthy" : "critical"}
            label={entry.reachable ? "Reachable" : "Unreachable"}
          />
        </div>
        {selected && <p className="text-xs text-muted-foreground">Selected</p>}
        {admin && !entry.reachable && (
          <p className="text-xs text-muted-foreground">
            {entry.status}: {entry.message}
          </p>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        <dl>
          <Fact label="Hostname" value={entry.hostname} />
          <Fact label="Version" value={entry.version} />
          <Fact label="Uptime" value={entry.uptime} />
        </dl>
        <div className="space-y-2">
          <Meter label="CPU" value={entry.cpu_used_percent} />
          <Meter label="Memory" value={entry.memory_used_percent} />
          <Meter label="Disk" value={entry.disk_used_percent} />
        </div>
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const { selected, select } = useSelectedFirewall();
  const [pollMs, setPollMs] = useState<number>(60_000); // in memory only
  const query = useQuery({
    queryKey: ["firewalls", "overview"],
    queryFn: api.getOverview,
    refetchInterval: pollMs > 0 ? pollMs : false,
  });
  const rows = query.data?.firewalls ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <label className="flex items-center gap-2">
            Refresh
            <SelectField
              value={String(pollMs)}
              onValueChange={(v) => setPollMs(Number(v))}
              options={POLL_OPTIONS.map((o) => ({ value: String(o.ms), label: o.label }))}
            />
          </label>
          <button
            type="button"
            className="h-9 rounded-md border border-border bg-card px-3"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh now
          </button>
        </div>
      </div>

      {query.isError && <ErrorState error={query.error} onRetry={() => void query.refetch()} />}

      {query.isPending && <Loading />}

      {query.isSuccess && rows.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">
            No firewalls configured.{" "}
            {admin ? (
              <>
                <Link className="text-primary underline" to="/administration/firewalls">
                  Add a firewall connection
                </Link>
                .
              </>
            ) : (
              "Ask an administrator to add one."
            )}
          </CardContent>
        </Card>
      )}

      {query.data?.truncated && (
        <p className="text-sm text-muted-foreground">
          Only the first firewalls are shown. The dashboard is limited to 50.
        </p>
      )}

      {rows.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {rows.map((f) => (
            <FirewallCard
              key={f.id}
              entry={f}
              selected={f.id === selected}
              admin={admin}
              onSelect={() => select(f.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
