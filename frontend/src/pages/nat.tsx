import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/features/auth/auth";
import { ForwardForm, toForwardProposal } from "@/features/changes/forward-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { ForwardProposalInput, NatRule } from "@/lib/schemas";

type Kind = "port-forwards" | "outbound";

type KindInfo = { id: Kind; label: string; description: string; excludedLabel: string };

const KINDS: [KindInfo, KindInfo] = [
  {
    id: "port-forwards",
    label: "Port forwards",
    description: "Destination NAT: traffic arriving at the firewall that is redirected to an internal address.",
    excludedLabel: "No redirect",
  },
  {
    id: "outbound",
    label: "Outbound",
    description: "Source NAT: how internal addresses are translated when leaving through an interface.",
    excludedLabel: "Do not NAT",
  },
];

function endpoint(host: string | null, port: string | null) {
  if (!host && !port) return "—";
  return `${host ?? "any"}${port ? `:${port}` : ""}`;
}

interface Actions {
  onToggle: (r: NatRule) => void;
  onEdit: (r: NatRule) => void;
  onDelete: (r: NatRule) => void;
}

function NatTable({ rules, kind, actions }: { rules: NatRule[]; kind: KindInfo; actions?: Actions }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>#</TableHead>
          <TableHead>Interface</TableHead>
          <TableHead>Protocol</TableHead>
          <TableHead>Source</TableHead>
          <TableHead>Destination</TableHead>
          <TableHead>{kind.id === "port-forwards" ? "Redirect to" : "Translate to"}</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Enabled</TableHead>
          {actions && <TableHead className="text-right">Change</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((r, n) => (
          <TableRow key={`${r.uuid ?? "?"}-${n}`}>
            <TableCell>{r.sequence ?? "—"}</TableCell>
            <TableCell>{r.interface ?? "—"}</TableCell>
            <TableCell>{[r.ip_protocol, r.protocol].filter(Boolean).join(" ") || "—"}</TableCell>
            <TableCell className="font-mono text-xs">{endpoint(r.source, r.source_port)}</TableCell>
            <TableCell className="font-mono text-xs">{endpoint(r.destination, r.destination_port)}</TableCell>
            <TableCell className="font-mono text-xs">
              {r.excluded ? <Badge>{kind.excludedLabel}</Badge> : endpoint(r.target, r.target_port)}
            </TableCell>
            <TableCell>
              {r.description ?? "—"}
              {r.automatic && <span className="ml-1 text-xs text-muted-foreground">(automatic)</span>}
            </TableCell>
            <TableCell>{r.enabled === null ? "—" : r.enabled ? "Yes" : "No"}</TableCell>
            {actions && (
              <TableCell className="text-right">
                {r.uuid && !r.automatic && !r.excluded && r.sequence !== null && r.description ? (
                  <div className="flex justify-end gap-1">
                    {r.enabled !== null && (
                      <Button size="sm" variant="outline" onClick={() => actions.onToggle(r)}>
                        {r.enabled ? "Disable" : "Enable"}
                      </Button>
                    )}
                    {toForwardProposal(r) && (
                      <Button size="sm" variant="outline" onClick={() => actions.onEdit(r)}>
                        <Pencil className="h-3 w-3" /> Edit
                      </Button>
                    )}
                    <Button size="sm" variant="outline" onClick={() => actions.onDelete(r)}>
                      <Trash2 className="h-3 w-3" /> Delete
                    </Button>
                  </div>
                ) : (
                  <span className="text-xs text-muted-foreground">Not editable here</span>
                )}
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function NatPage() {
  const { hasRole } = useAuth();
  const canManage = hasRole("admin", "network_admin");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<NatRule | null>(null);
  const [toggling, setToggling] = useState<NatRule | null>(null);
  const [deleting, setDeleting] = useState<NatRule | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);
  const close = () => {
    setCreating(false);
    setEditing(null);
    setToggling(null);
    setDeleting(null);
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
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [kindId, setKindId] = useState<Kind>("port-forwards");
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;
  const kind = KINDS.find((k) => k.id === kindId) ?? KINDS[0];

  const q = useQuery({
    queryKey: ["firewalls", selected, "nat", kindId],
    queryFn: () => api.natRules(selected as string, kindId),
    enabled: selected !== null,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">NAT</h1>
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

      {options.isError && <ErrorState error={options.error} onRetry={() => void options.refetch()} />}
      {options.isSuccess && firewalls.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">No firewalls configured.</CardContent>
        </Card>
      )}

      {selected && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              {kind.label} {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>
              {kind.description} {kind.id === "port-forwards" && canManage ? "Changes go through a reviewed request." : "Read-only."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex gap-2" role="group" aria-label="NAT type">
              {KINDS.map((k) => (
                <Button
                  key={k.id}
                  size="sm"
                  variant={kindId === k.id ? "default" : "outline"}
                  aria-pressed={kindId === k.id}
                  onClick={() => setKindId(k.id)}
                >
                  {k.label}
                </Button>
              ))}
              {kind.id === "port-forwards" && canManage && (
                <Button size="sm" className="ml-auto" onClick={() => setCreating(true)}>
                  <Plus className="h-4 w-4" /> New port forward
                </Button>
              )}
            </div>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall reported no {kind.label.toLowerCase()}.</p>
            ) : (
              <>
                {q.data.truncated && <p className="text-sm text-muted-foreground">Only the first rules are shown.</p>}
                <NatTable
                  rules={q.data.rules}
                  kind={kind}
                  actions={
                    kind.id === "port-forwards" && canManage
                      ? { onToggle: setToggling, onEdit: setEditing, onDelete: setDeleting }
                      : undefined
                  }
                />
              </>
            )}
          </CardContent>
        </Card>
      )}
      <Dialog open={creating || editing !== null} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? `Change port forward ${editing.description}` : "New port forward"}</DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it is reviewed, approved and applied.
            </DialogDescription>
          </DialogHeader>
          {(creating || (editing && toForwardProposal(editing))) && (
            <ForwardForm
              initial={editing ? (toForwardProposal(editing) as ForwardProposalInput) : undefined}
              pending={pending}
              error={changeError}
              onCancel={close}
              onSubmit={(forward) => {
                if (!selected) return;
                if (editing?.uuid) stage(() => api.stageForwardUpdate(selected, editing.uuid as string, forward));
                else stage(() => api.stageForward(selected, forward));
              }}
            />
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && close()}
        title={toggling?.enabled ? "Request disabling this port forward?" : "Request enabling this port forward?"}
        confirmLabel="Create change request"
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a change request for the port forward <strong>{toggling?.description}</strong>. Nothing is
            sent to the firewall until it is reviewed, approved and applied.
          </>
        }
        onConfirm={() => {
          if (!toggling?.uuid || !selected) return;
          const target = toggling;
          stage(() => api.stageForwardToggle(selected, target.uuid as string, !target.enabled));
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this port forward?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete the port forward <strong>{deleting?.description}</strong>.
            Nothing is sent to the firewall until an admin approves it and applies it by typing the description.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid || !selected) return;
          const target = deleting;
          stage(() => api.stageForwardDelete(selected, target.uuid as string));
        }}
      />
    </div>
  );
}
