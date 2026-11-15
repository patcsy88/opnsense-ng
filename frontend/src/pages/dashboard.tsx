import { SelectField } from "@/components/ui/select-field";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/features/auth/auth";
import { ConnectivityCard, SystemStatusCard } from "@/features/dashboard/firewall-cards";
import { useSelectedFirewall } from "@/features/firewall/selected-firewall";

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
  const [pollMs, setPollMs] = useState<number>(30_000); // in memory only
  const { options: list, firewalls, selected } = useSelectedFirewall();

  const interval = pollMs > 0 ? pollMs : false;

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
        </div>
      </div>

      {list.isError && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}

      {list.isSuccess && firewalls.length === 0 && (
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

      {selected && (
        <div className="grid gap-4 lg:grid-cols-2">
          <ConnectivityCard firewallId={selected} intervalMs={interval} />
          <SystemStatusCard firewallId={selected} intervalMs={interval} />
        </div>
      )}
    </div>
  );
}
