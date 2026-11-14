import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/features/auth/auth";
import { api } from "@/lib/api";

const INTERVALS = [
  { label: "30 s", ms: 30_000 },
  { label: "60 s", ms: 60_000 },
  { label: "Off", ms: 0 },
] as const;

const pct = (v: number | null) => (v === null ? "–" : `${v.toFixed(0)}%`);

export function OverviewPage() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
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
        <h1 className="text-2xl font-semibold">Overview</h1>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <label className="flex items-center gap-2">
            Refresh
            <select
              className="h-9 rounded-md border border-border bg-card px-2"
              value={pollMs}
              onChange={(e) => setPollMs(Number(e.target.value))}
            >
              {INTERVALS.map((o) => (
                <option key={o.ms} value={o.ms}>
                  {o.label}
                </option>
              ))}
            </select>
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

      {query.isError && (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      )}

      {query.isSuccess && rows.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">
            No firewalls configured.
          </CardContent>
        </Card>
      )}

      {query.data?.truncated && (
        <p className="text-sm text-muted-foreground">
          Only the first firewalls are shown. The overview is limited to 50.
        </p>
      )}

      {rows.length > 0 && (
        <Card>
          <CardContent className="overflow-x-auto pt-4">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="py-2 pr-3">Firewall</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Hostname</th>
                  <th className="py-2 pr-3">Version</th>
                  <th className="py-2 pr-3">Uptime</th>
                  <th className="py-2 pr-3">CPU</th>
                  <th className="py-2 pr-3">Memory</th>
                  <th className="py-2">Disk</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr
                    key={f.id}
                    className="border-b border-border last:border-0"
                  >
                    <td className="py-2 pr-3">
                      <Link
                        className="text-primary underline"
                        to={`/?fw=${f.id}`}
                      >
                        {f.name}
                      </Link>
                    </td>
                    <td className="py-2 pr-3">
                      <span className={f.reachable ? "" : "text-destructive"}>
                        {f.reachable ? "Reachable" : "Unreachable"}
                      </span>
                      {admin && !f.reachable && (
                        <span className="block text-xs text-muted-foreground">
                          {f.status}: {f.message}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-3">{f.hostname ?? "–"}</td>
                    <td className="py-2 pr-3">{f.version ?? "–"}</td>
                    <td className="py-2 pr-3">{f.uptime ?? "–"}</td>
                    <td className="py-2 pr-3">{pct(f.cpu_used_percent)}</td>
                    <td className="py-2 pr-3">{pct(f.memory_used_percent)}</td>
                    <td className="py-2">{pct(f.disk_used_percent)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
