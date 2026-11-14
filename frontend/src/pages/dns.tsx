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
import { UnboundForwards } from "@/features/changes/unbound-forwards";
import { UnboundHosts } from "@/features/changes/unbound-hosts";
import { useAuth } from "@/features/auth/auth";
import { api } from "@/lib/api";
import type { TopDomain } from "@/lib/schemas";

function count(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

function uptime(seconds: number | null): string {
  if (seconds === null) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days > 0
    ? `${days}d ${hours}h`
    : hours > 0
      ? `${hours}h ${minutes}m`
      : `${minutes}m`;
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}

function TopTable({
  title,
  rows,
  blocklist,
}: {
  title: string;
  rows: TopDomain[];
  blocklist: boolean;
}) {
  return (
    <section className="space-y-2" aria-label={title}>
      <h2 className="text-lg font-medium">{title}</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No data.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Domain</TableHead>
              <TableHead>Queries</TableHead>
              {blocklist && <TableHead>Blocklist</TableHead>}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.domain}>
                <TableCell className="font-mono text-xs sm:text-sm">
                  {r.domain}
                </TableCell>
                <TableCell>{count(r.count)}</TableCell>
                {blocklist && <TableCell>{r.blocklist ?? "—"}</TableCell>}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  );
}

export function DnsPage() {
  const options = useQuery({
    queryKey: ["firewalls", "options"],
    queryFn: api.listFirewallOptions,
  });
  const { hasRole } = useAuth();
  const canManage = hasRole("admin") || hasRole("network_admin");
  const [tab, setTab] = useState<"overview" | "hosts" | "forwards">("overview");
  const [chosen, setChosen] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "dns"],
    queryFn: () => api.dns(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });
  const d = q.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">DNS</h1>
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
      {canManage && (
        <div role="tablist" aria-label="DNS section" className="flex gap-2">
          {(
            [
              ["overview", "Overview"],
              ["hosts", "Host overrides"],
              ["forwards", "Domain forwards"],
            ] as const
          ).map(([id, text]) => (
            <Button
              key={id}
              role="tab"
              aria-selected={tab === id}
              size="sm"
              variant={tab === id ? "default" : "outline"}
              onClick={() => setTab(id)}
            >
              {text}
            </Button>
          ))}
        </div>
      )}

      {canManage && tab === "hosts" && selected && (
        <UnboundHosts firewallId={selected} />
      )}
      {canManage && tab === "forwards" && selected && (
        <UnboundForwards firewallId={selected} />
      )}
      {tab === "overview" && q.isError && (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      )}

      {tab === "overview" && selected && !q.isError && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              Unbound resolver{" "}
              {d && !d.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              Read-only overview. Per-client queries are not shown, and DNS
              settings cannot be changed here. Refreshes every 30 seconds.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {q.isPending || !d ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading…
              </p>
            ) : (
              <>
                {d.stats_available ? (
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <Stat label="Queries" value={count(d.queries)} />
                    <Stat
                      label="Cache hit rate"
                      value={d.hit_rate === null ? "—" : `${d.hit_rate}%`}
                    />
                    <Stat label="Cache misses" value={count(d.cache_misses)} />
                    <Stat label="Uptime" value={uptime(d.uptime_seconds)} />
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Resolver counters are not available. Check that Unbound is
                    running.
                  </p>
                )}
                {d.totals_available ? (
                  <>
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                      <Stat
                        label="Logged queries"
                        value={count(d.logged_queries)}
                      />
                      <Stat label="Blocked" value={count(d.blocked)} />
                      <Stat
                        label="Blocked share"
                        value={
                          d.blocked_percent === null
                            ? "—"
                            : `${d.blocked_percent}%`
                        }
                      />
                      <Stat
                        label="Blocklist size"
                        value={count(d.blocklist_size)}
                      />
                    </div>
                    <div className="grid gap-6 lg:grid-cols-2">
                      <TopTable
                        title="Top queried domains"
                        rows={d.top_queried}
                        blocklist={false}
                      />
                      <TopTable
                        title="Top blocked domains"
                        rows={d.top_blocked}
                        blocklist
                      />
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No query statistics yet. Turn on Extended Statistics in
                    Services, Unbound DNS, Advanced, and allow some time for
                    queries to be recorded.
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
