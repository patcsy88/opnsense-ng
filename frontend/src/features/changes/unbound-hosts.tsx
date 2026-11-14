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
  UnboundHostForm,
  toUnboundProposal,
} from "@/features/changes/unbound-host-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { UnboundHost, UnboundHostProposalInput } from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function UnboundHosts({ firewallId }: { firewallId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<UnboundHost | null>(null);
  const [deleting, setDeleting] = useState<UnboundHost | null>(null);
  const [toggling, setToggling] = useState<UnboundHost | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", firewallId, "unbound-hosts"],
    queryFn: () => api.unboundHosts(firewallId),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", firewallId],
    queryFn: () => api.listChanges({ firewallId }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "unbound_host" && OPEN.has(c.status),
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
  const editable = editing ? toUnboundProposal(editing) : null;
  const label = (h: UnboundHost) =>
    h.description ?? h.hostname ?? "host override";

  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              Host overrides{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </span>
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-4 w-4" aria-hidden /> New host override
            </Button>
          </CardTitle>
          <CardDescription>
            Local DNS names answered by Unbound (A and AAAA records). Changes go
            through a reviewed request, and applying restarts Unbound, which
            pauses DNS for every client.
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
                      {c.action} {String(c.proposed?.label ?? "host override")}
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
              The firewall has no host overrides.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Record</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {q.data.hosts.map((h) => (
                    <TableRow
                      key={h.uuid ?? `${h.hostname}.${h.domain}.${h.rr}`}
                    >
                      <TableCell className="font-mono text-xs">
                        {h.hostname ?? "—"}
                        {h.domain ? `.${h.domain}` : ""}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {h.rr ?? "—"} {h.server ?? ""}
                      </TableCell>
                      <TableCell>{h.description ?? "—"}</TableCell>
                      <TableCell>
                        {h.enabled ? "Enabled" : <Badge>Disabled</Badge>}
                      </TableCell>
                      <TableCell className="space-x-2">
                        {h.editable && h.uuid ? (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Edit host override ${label(h)}`}
                              onClick={() => setEditing(h)}
                            >
                              <Pencil className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`${h.enabled ? "Disable" : "Enable"} host override ${label(h)}`}
                              onClick={() => setToggling(h)}
                            >
                              <Power className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Delete host override ${label(h)}`}
                              onClick={() => setDeleting(h)}
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
              {editing
                ? `Change host override ${editing.description}`
                : "New host override"}
            </DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it
              is approved and applied.
            </DialogDescription>
          </DialogHeader>
          <UnboundHostForm
            initial={editable ?? undefined}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(host: UnboundHostProposalInput) => {
              if (editing?.uuid)
                stage(() =>
                  api.stageUnboundHostUpdate(
                    firewallId,
                    editing.uuid as string,
                    host,
                  ),
                );
              else stage(() => api.stageUnboundHost(firewallId, host));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this host override?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete{" "}
            <strong>{deleting ? label(deleting) : ""}</strong>. Nothing is sent
            to the firewall until an admin approves it and applies it by typing
            the description.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid) return;
          const target = deleting;
          stage(() =>
            api.stageUnboundHostDelete(firewallId, target.uuid as string),
          );
        }}
      />
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && close()}
        title={
          toggling?.enabled
            ? "Request disabling this host override?"
            : "Request enabling this host override?"
        }
        confirmLabel="Create change request"
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a change request to{" "}
            {toggling?.enabled ? "disable" : "enable"}{" "}
            <strong>{toggling ? label(toggling) : ""}</strong>. Nothing is sent
            to the firewall until it is approved and applied.
          </>
        }
        onConfirm={() => {
          if (!toggling?.uuid) return;
          const target = toggling;
          stage(() =>
            api.stageUnboundHostToggle(
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
