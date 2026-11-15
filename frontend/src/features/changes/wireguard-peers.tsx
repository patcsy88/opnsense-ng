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
import {
  WireguardPeerForm,
  toWireguardPeerProposal,
} from "@/features/changes/wireguard-peer-form";
import { ChangeStatusBadge } from "@/features/changes/status";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { WireguardPeer, WireguardPeerProposalInput } from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function WireguardPeers({ firewallId }: { firewallId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<WireguardPeer | null>(null);
  const [deleting, setDeleting] = useState<WireguardPeer | null>(null);
  const [toggling, setToggling] = useState<WireguardPeer | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", firewallId, "wireguard-peers"],
    queryFn: () => api.wireguardPeers(firewallId),
  });
  const tunnels = useQuery({
    queryKey: ["firewalls", firewallId, "wireguard-tunnels"],
    queryFn: () => api.wireguardTunnels(firewallId),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", firewallId],
    queryFn: () => api.listChanges({ firewallId }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "wireguard_peer" && OPEN.has(c.status),
  );
  const tunnelName = (id: string) =>
    tunnels.data?.tunnels.find((t) => t.uuid === id)?.name ?? id.slice(0, 8);

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
  const editable = editing ? toWireguardPeerProposal(editing) : null;
  const label = (p: WireguardPeer) => p.name ?? "peer";

  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              Peers {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </span>
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-4 w-4" aria-hidden /> New peer
            </Button>
          </CardTitle>
          <CardDescription>
            VPN peers configured on the firewall. Changes go through a reviewed
            request, and applying reconfigures WireGuard, so active sessions may
            drop. Only public keys are used here.
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
                      {c.action} {String(c.proposed?.label ?? "peer")}
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
          ) : q.data.peers.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The firewall has no peers.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Tunnels</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Public key</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {q.data.peers.map((p) => (
                    <TableRow key={p.uuid ?? String(p.pubkey)}>
                      <TableCell>{p.name ?? "—"}</TableCell>
                      <TableCell>
                        {p.servers.length
                          ? p.servers.map(tunnelName).join(", ")
                          : "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {p.tunneladdress.length
                          ? p.tunneladdress.join(", ")
                          : "—"}
                      </TableCell>
                      <TableCell className="max-w-[14rem] break-all font-mono text-xs">
                        {p.pubkey ?? "—"}
                        {p.has_psk && (
                          <span className="ml-1 text-muted-foreground">
                            (preshared key set)
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        {p.enabled ? "Enabled" : <Badge>Disabled</Badge>}
                      </TableCell>
                      <TableCell className="space-x-2">
                        {p.uuid ? (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Edit peer ${label(p)}`}
                              onClick={() => setEditing(p)}
                            >
                              <Pencil className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`${p.enabled ? "Disable" : "Enable"} peer ${label(p)}`}
                              onClick={() => setToggling(p)}
                            >
                              <Power className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Delete peer ${label(p)}`}
                              onClick={() => setDeleting(p)}
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
        <DialogContent className="p-6">
          <DialogHeader className="p-0 pb-3">
            <DialogTitle>
              {editing ? `Change peer ${editing.name}` : "New peer"}
            </DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it
              is approved and applied.
            </DialogDescription>
          </DialogHeader>
          <WireguardPeerForm
            initial={editable ?? undefined}
            tunnels={tunnels.data?.tunnels ?? []}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(peer: WireguardPeerProposalInput) => {
              if (editing?.uuid)
                stage(() =>
                  api.stageWireguardPeerUpdate(
                    firewallId,
                    editing.uuid as string,
                    peer,
                  ),
                );
              else stage(() => api.stageWireguardPeer(firewallId, peer));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this peer?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete{" "}
            <strong>{deleting ? label(deleting) : ""}</strong>, which removes
            its VPN access. Nothing is sent to the firewall until an admin
            approves it and applies it by typing the peer name.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid) return;
          const target = deleting;
          stage(() =>
            api.stageWireguardPeerDelete(firewallId, target.uuid as string),
          );
        }}
      />
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && close()}
        title={
          toggling?.enabled
            ? "Request disabling this peer?"
            : "Request enabling this peer?"
        }
        confirmLabel="Create change request"
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a change request to{" "}
            {toggling?.enabled ? "disable" : "enable"}{" "}
            <strong>{toggling ? label(toggling) : ""}</strong>
            {toggling?.enabled
              ? ", which cuts its access, so it is high risk"
              : ""}
            . Nothing is sent to the firewall until it is approved and applied.
          </>
        }
        onConfirm={() => {
          if (!toggling?.uuid) return;
          const target = toggling;
          stage(() =>
            api.stageWireguardPeerToggle(
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
