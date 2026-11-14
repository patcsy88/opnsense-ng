import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
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
import { HostForm, toHostProposal } from "@/features/changes/host-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { DnsmasqHost, HostProposalInput } from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function DnsEntriesPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const options = useQuery({
    queryKey: ["firewalls", "options"],
    queryFn: api.listFirewallOptions,
  });
  const [chosen, setChosen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<DnsmasqHost | null>(null);
  const [deleting, setDeleting] = useState<DnsmasqHost | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "dnsmasq-hosts"],
    queryFn: () => api.dnsmasqHosts(selected as string),
    enabled: selected !== null,
  });
  const changes = useQuery({
    queryKey: ["changes", "list", selected],
    queryFn: () => api.listChanges({ firewallId: selected as string }),
    enabled: selected !== null,
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "dnsmasq_host" && OPEN.has(c.status),
  );

  const close = () => {
    setCreating(false);
    setEditing(null);
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
        navigate(`/changes/${made.id}`);
      })
      .catch((e: unknown) => setChangeError(describeError(e).message))
      .finally(() => setPending(false));
  };
  const editable = editing ? toHostProposal(editing) : null;

  return (
    <div className="space-y-4">
      <p className="text-sm">
        <Link className="text-primary underline" to="/dhcp">
          ← DHCP
        </Link>
      </p>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">DNS and DHCP entries</h1>
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
      {q.isError && (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      )}

      {selected && !q.isError && (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2">
                Static hosts{" "}
                {q.data && !q.data.registry_verified && <UnverifiedBadge />}
              </span>
              <Button size="sm" onClick={() => setCreating(true)}>
                <Plus className="mr-1 h-4 w-4" aria-hidden /> New host
              </Button>
            </CardTitle>
            <CardDescription>
              Dnsmasq host entries on the firewall, with MAC addresses. Changes
              are requests: nothing is sent until they are reviewed, approved
              and applied, and applying restarts Dnsmasq.
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
                        to={`/changes/${c.id}`}
                      >
                        {c.action} {String(c.proposed?.label ?? "host")}
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
            ) : q.data.hosts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                The firewall has no static host entries.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>IP addresses</TableHead>
                      <TableHead>MAC addresses</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {q.data.hosts.map((h) => (
                      <TableRow key={h.uuid ?? `${h.host}.${h.domain}`}>
                        <TableCell className="font-mono text-xs">
                          {h.host ?? "—"}
                          {h.domain ? `.${h.domain}` : ""}{" "}
                          {h.ignore && <Badge variant="warning">ignored</Badge>}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {h.ips.join(", ") || "—"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {h.hwaddrs.join(", ") || "—"}
                        </TableCell>
                        <TableCell>{h.description ?? "—"}</TableCell>
                        <TableCell className="space-x-2">
                          {toHostProposal(h) && (
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Edit ${h.description}`}
                              onClick={() => setEditing(h)}
                            >
                              <Pencil className="h-4 w-4" aria-hidden />
                            </Button>
                          )}
                          {h.uuid && (
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Delete ${h.description ?? h.host}`}
                              onClick={() => setDeleting(h)}
                            >
                              <Trash2 className="h-4 w-4" aria-hidden />
                            </Button>
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
      )}

      <Dialog
        open={creating || editable !== null}
        onOpenChange={(o) => !o && close()}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editing
                ? `Change host ${editing.description}`
                : "New static host"}
            </DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it
              is reviewed, approved and applied.
            </DialogDescription>
          </DialogHeader>
          <HostForm
            initial={editable ?? undefined}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(host: HostProposalInput) => {
              if (!selected) return;
              if (editing?.uuid)
                stage(() =>
                  api.stageHostUpdate(selected, editing.uuid as string, host),
                );
              else stage(() => api.stageHost(selected, host));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this host entry?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete{" "}
            <strong>{deleting?.description ?? deleting?.host}</strong>. Nothing
            is sent to the firewall until an admin approves it and applies it by
            typing the description.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid || !selected) return;
          const target = deleting;
          stage(() => api.stageHostDelete(selected, target.uuid as string));
        }}
      />
    </div>
  );
}
