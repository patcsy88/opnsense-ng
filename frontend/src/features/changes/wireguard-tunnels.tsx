import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Power, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ChangeStatusBadge } from "@/features/changes/status";
import {
  WireguardTunnelForm,
  toWireguardTunnelProposal,
} from "@/features/changes/wireguard-tunnel-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type {
  WireguardTunnel,
  WireguardTunnelProposalInput,
} from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function WireguardTunnels({ firewallId }: { firewallId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<WireguardTunnel | null>(null);
  const [deleting, setDeleting] = useState<WireguardTunnel | null>(null);
  const [toggling, setToggling] = useState<WireguardTunnel | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", firewallId, "wireguard-tunnels"],
    queryFn: () => api.wireguardTunnels(firewallId),
  });
  const peers = useQuery({
    queryKey: ["firewalls", firewallId, "wireguard-peers"],
    queryFn: () => api.wireguardPeers(firewallId),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", firewallId],
    queryFn: () => api.listChanges({ firewallId }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "wireguard_tunnel" && OPEN.has(c.status),
  );

  const close = () => {
    setCreating(false);
    setEditing(null);
    setDeleting(null);
    setToggling(null);
    setChangeError(null);
  };
  const stage = (run: () => Promise<{ id: string }>) => {
    setChangeError(null);
    setPending(true);
    run()
      .then(async (made) => {
        await qc.invalidateQueries({ queryKey: ["changes"] });
        close();
        navigate(`/administration/changes/${made.id}`);
      })
      .catch((e: unknown) => setChangeError(describeError(e).message))
      .finally(() => setPending(false));
  };
  const editable = editing ? toWireguardTunnelProposal(editing) : null;
  const label = (t: WireguardTunnel) => t.name ?? "tunnel";

  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              Tunnels{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </span>
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-4 w-4" aria-hidden /> New tunnel
            </Button>
          </CardTitle>
          <CardDescription>
            WireGuard tunnels on the firewall. Every change is high risk and
            needs an admin to approve it. Private keys are never read, shown or
            sent; the firewall makes a new tunnel&apos;s key itself.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {open.length > 0 && (
            <div className="rounded-md border border-border p-2 text-sm">
              <p className="font-medium">Open requests</p>
              <ul className="mt-1 space-y-1">
                {open.map((c) => (
                  <li key={c.id} className="flex items-center gap-2">
                    <ChangeStatusBadge status={c.status} />
                    <Link
                      className="text-primary underline"
                      to={`/administration/changes/${c.id}`}
                    >
                      {c.action} {String(c.proposed?.label ?? "tunnel")}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
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
                    <TableHead>Actions</TableHead>
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
                      <TableCell className="space-x-2">
                        {t.uuid ? (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Edit tunnel ${label(t)}`}
                              onClick={() => setEditing(t)}
                            >
                              <Pencil className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`${t.enabled ? "Disable" : "Enable"} tunnel ${label(t)}`}
                              onClick={() => setToggling(t)}
                            >
                              <Power className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Delete tunnel ${label(t)}`}
                              onClick={() => setDeleting(t)}
                            >
                              <Trash2 className="h-4 w-4" aria-hidden />
                            </Button>
                          </>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Not editable here
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={creating || editable !== null}
        onOpenChange={(o) => !o && close()}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editing ? `Change tunnel ${editing.name}` : "New tunnel"}
            </DialogTitle>
            <DialogDescription>
              Creates a high-risk change request. Nothing is sent to the
              firewall until an admin approves and applies it.
            </DialogDescription>
          </DialogHeader>
          <WireguardTunnelForm
            initial={editable ?? undefined}
            peers={peers.data?.peers ?? []}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(tunnel: WireguardTunnelProposalInput) => {
              if (editing?.uuid)
                stage(() =>
                  api.stageWireguardTunnelUpdate(
                    firewallId,
                    editing.uuid as string,
                    tunnel,
                  ),
                );
              else stage(() => api.stageWireguardTunnel(firewallId, tunnel));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this tunnel?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete{" "}
            <strong>{deleting ? label(deleting) : ""}</strong>, which removes
            all of its VPN access. An admin approves it and applies it by typing
            the tunnel name.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid) return;
          const target = deleting;
          stage(() =>
            api.stageWireguardTunnelDelete(firewallId, target.uuid as string),
          );
        }}
      />
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && close()}
        title={
          toggling?.enabled
            ? "Request disabling this tunnel?"
            : "Request enabling this tunnel?"
        }
        confirmLabel="Create change request"
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to{" "}
            {toggling?.enabled ? "disable" : "enable"}{" "}
            <strong>{toggling ? label(toggling) : ""}</strong>, which{" "}
            {toggling?.enabled ? "cuts" : "starts"} all of its VPN traffic.
          </>
        }
        onConfirm={() => {
          if (!toggling?.uuid) return;
          const target = toggling;
          stage(() =>
            api.stageWireguardTunnelToggle(
              firewallId,
              target.uuid as string,
              !target.enabled,
            ),
          );
        }}
      />
    </>
  );
}
