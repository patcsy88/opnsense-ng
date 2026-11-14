import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
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
import { useAuth } from "@/features/auth/auth";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { ServiceInfo } from "@/lib/schemas";

type Action = "start" | "stop" | "restart";

// Mirrors the backend lists (ADR-0016) only to choose buttons and dialogs. The backend enforces them.
const PROTECTED = new Set(["configd", "webgui"]);
const HIGH_IMPACT = new Set([
  "unbound",
  "dnsmasq",
  "dhcpd",
  "dhcpd6",
  "dhcrelay",
  "kea-dhcp4",
  "kea-dhcp6",
  "radvd",
  "wireguard",
  "openvpn",
  "ipsec",
  "strongswan",
  "ntpd",
  "chronyd",
  "syslog-ng",
]);

interface Pending {
  service: ServiceInfo;
  action: Action;
}

export function ServicesPage() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const queryClient = useQueryClient();
  const [pending, setPending] = useState<Pending | null>(null);
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string } | null>(
    null,
  );
  const options = useQuery({
    queryKey: ["firewalls", "options"],
    queryFn: api.listFirewallOptions,
  });
  const [chosen, setChosen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "services"],
    queryFn: () => api.services(selected as string),
    enabled: selected !== null,
    refetchInterval: 30_000,
  });

  // Only admins can read allow_writes (the selector list has id and name only).
  const full = useQuery({
    queryKey: ["firewalls"],
    queryFn: api.listFirewalls,
    enabled: admin,
  });
  const writesOn =
    full.data?.find((f) => f.id === selected)?.allow_writes === true;
  const canControl = admin && writesOn;

  const control = useMutation({
    mutationFn: (v: Pending & { typed?: string }) =>
      api.controlService(selected as string, v.action, {
        service: v.service.name,
        instance: v.service.instance ?? null,
        confirm_name: v.typed,
      }),
    onSuccess: async (res) => {
      setPending(null);
      setOutcome({ ok: res.confirmed, text: `${res.service}: ${res.message}` });
      await queryClient.invalidateQueries({
        queryKey: ["firewalls", selected, "services"],
      });
    },
  });

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const rows = q.data?.services ?? [];
    return needle
      ? rows.filter((s) =>
          `${s.name} ${s.description ?? ""}`.toLowerCase().includes(needle),
        )
      : rows;
  }, [q.data, text]);
  const stopped = (q.data?.services ?? []).filter((s) => !s.running).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Services</h1>
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
              Service status{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              {canControl
                ? "Start, stop and restart need confirmation and cannot be undone automatically."
                : admin && full.isSuccess
                  ? "Read-only: enable changes for this firewall in Administration to control services."
                  : "Read-only."}{" "}
              Refreshes every 30 seconds.
              {q.data &&
                ` ${q.data.services.length} services, ${stopped} not running.`}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading…
              </p>
            ) : (
              <>
                <Input
                  aria-label="Filter services"
                  placeholder="Filter by name or description"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className="max-w-xs"
                />
                {shown.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No services match.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Status</TableHead>
                        {canControl && <TableHead>Actions</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {shown.map((s) => (
                        <TableRow key={s.id}>
                          <TableCell className="font-mono text-xs sm:text-sm">
                            {s.id}
                          </TableCell>
                          <TableCell>{s.description ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant={s.running ? "success" : "critical"}>
                              {s.running ? "Running" : "Stopped"}
                            </Badge>
                            {s.locked && (
                              <span className="ml-2 text-xs text-muted-foreground">
                                locked
                              </span>
                            )}
                          </TableCell>
                          {canControl && (
                            <TableCell className="space-x-2">
                              {s.locked ||
                              (PROTECTED.has(s.name) && s.running) ? (
                                <span className="text-xs text-muted-foreground">
                                  not available here
                                </span>
                              ) : (
                                <>
                                  {!s.running && (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() =>
                                        setPending({
                                          service: s,
                                          action: "start",
                                        })
                                      }
                                    >
                                      Start
                                    </Button>
                                  )}
                                  {s.running && !PROTECTED.has(s.name) && (
                                    <>
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() =>
                                          setPending({
                                            service: s,
                                            action: "restart",
                                          })
                                        }
                                      >
                                        Restart
                                      </Button>
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() =>
                                          setPending({
                                            service: s,
                                            action: "stop",
                                          })
                                        }
                                      >
                                        Stop
                                      </Button>
                                    </>
                                  )}
                                </>
                              )}
                            </TableCell>
                          )}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {outcome && (
                  <p
                    role="status"
                    className={`text-sm ${outcome.ok ? "" : "text-destructive"}`}
                  >
                    {outcome.text}
                  </p>
                )}
                {q.data?.truncated && (
                  <p className="text-xs text-muted-foreground">
                    The list was cut off at 500 services.
                  </p>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}

      {pending && (
        <ConfirmDialog
          open
          onOpenChange={(o) => {
            if (!o) {
              setPending(null);
              control.reset();
            }
          }}
          title={`${pending.action[0]?.toUpperCase()}${pending.action.slice(1)} ${pending.service.name}?`}
          description={
            <>
              This {pending.action}s <strong>{pending.service.name}</strong> on{" "}
              <strong>{firewalls.find((f) => f.id === selected)?.name}</strong>{" "}
              now. It is not rolled back automatically. The result is read back
              from the firewall, not assumed.
            </>
          }
          confirmLabel={
            pending.action[0]?.toUpperCase() + pending.action.slice(1)
          }
          destructive={pending.action !== "start"}
          requireText={
            pending.action !== "start" && HIGH_IMPACT.has(pending.service.name)
              ? pending.service.name
              : undefined
          }
          pending={control.isPending}
          error={control.isError ? describeError(control.error).message : null}
          onConfirm={() =>
            control.mutate({
              ...pending,
              typed: HIGH_IMPACT.has(pending.service.name)
                ? pending.service.name
                : undefined,
            })
          }
        />
      )}
    </div>
  );
}
