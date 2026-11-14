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
  UnboundForwardForm,
  toUnboundForwardProposal,
} from "@/features/changes/unbound-forward-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type {
  UnboundForward,
  UnboundForwardProposalInput,
} from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function UnboundForwards({ firewallId }: { firewallId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<UnboundForward | null>(null);
  const [deleting, setDeleting] = useState<UnboundForward | null>(null);
  const [toggling, setToggling] = useState<UnboundForward | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", firewallId, "unbound-forwards"],
    queryFn: () => api.unboundForwards(firewallId),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", firewallId],
    queryFn: () => api.listChanges({ firewallId }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "unbound_forward" && OPEN.has(c.status),
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
  const editable = editing ? toUnboundForwardProposal(editing) : null;
  const label = (h: UnboundForward) => h.description ?? h.domain ?? "forward";

  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              Domain forwards{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </span>
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-4 w-4" aria-hidden /> New forward
            </Button>
          </CardTitle>
          <CardDescription>
            Domains that Unbound asks another DNS server about. Every change is
            high risk, goes through a reviewed request, and applying restarts
            Unbound, which pauses DNS for every client.
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
                      {c.action} {String(c.proposed?.label ?? "forward")}
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
          ) : q.data.forwards.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The firewall has no forwards.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Domain</TableHead>
                    <TableHead>DNS server</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {q.data.forwards.map((h) => (
                    <TableRow key={h.uuid ?? String(h.domain)}>
                      <TableCell className="font-mono text-xs">
                        {h.domain ?? "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {h.server ?? "—"}
                        {h.port ? `:${h.port}` : ""}
                      </TableCell>
                      <TableCell>{h.description ?? "—"}</TableCell>
                      <TableCell>
                        {h.enabled ? "Enabled" : <Badge>Disabled</Badge>}
                      </TableCell>
                      <TableCell className="space-x-2">
                        {h.uuid ? (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Edit forward ${label(h)}`}
                              onClick={() => setEditing(h)}
                            >
                              <Pencil className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`${h.enabled ? "Disable" : "Enable"} forward ${label(h)}`}
                              onClick={() => setToggling(h)}
                            >
                              <Power className="h-4 w-4" aria-hidden />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Delete forward ${label(h)}`}
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
                ? `Change forward ${editing.description}`
                : "New forward"}
            </DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it
              is approved and applied.
            </DialogDescription>
          </DialogHeader>
          <UnboundForwardForm
            initial={editable ?? undefined}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(forward: UnboundForwardProposalInput) => {
              if (editing?.uuid)
                stage(() =>
                  api.stageUnboundForwardUpdate(
                    firewallId,
                    editing.uuid as string,
                    forward,
                  ),
                );
              else stage(() => api.stageUnboundForward(firewallId, forward));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this forward?"
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
            api.stageUnboundForwardDelete(firewallId, target.uuid as string),
          );
        }}
      />
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && close()}
        title={
          toggling?.enabled
            ? "Request disabling this forward?"
            : "Request enabling this forward?"
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
            api.stageUnboundForwardToggle(
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
