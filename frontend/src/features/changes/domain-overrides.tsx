import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
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
import { DomainForm, toDomainProposal } from "@/features/changes/domain-form";
import { ChangeStatusBadge } from "@/features/changes/status";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { DnsmasqDomain, DomainProposalInput } from "@/lib/schemas";

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

export function DomainOverrides({ firewallId }: { firewallId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<DnsmasqDomain | null>(null);
  const [deleting, setDeleting] = useState<DnsmasqDomain | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", firewallId, "dnsmasq-domains"],
    queryFn: () => api.dnsmasqDomains(firewallId),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", firewallId],
    queryFn: () => api.listChanges({ firewallId }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "dnsmasq_domain" && OPEN.has(c.status),
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
  const editable = editing ? toDomainProposal(editing) : null;

  if (q.isError)
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              Domain overrides{" "}
              {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </span>
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-4 w-4" aria-hidden /> New override
            </Button>
          </CardTitle>
          <CardDescription>
            Send lookups for a domain to a specific DNS server. Every change is
            high risk: it needs an admin to approve it and the description typed
            to apply it, and applying restarts Dnsmasq.
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
                      {c.action} {String(c.proposed?.label ?? "override")}
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
          ) : q.data.domains.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The firewall has no domain overrides.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Domain</TableHead>
                    <TableHead>DNS server</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {q.data.domains.map((d) => (
                    <TableRow key={d.uuid ?? d.domain}>
                      <TableCell className="font-mono text-xs">
                        {d.domain ?? "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {d.server ?? "—"}
                        {d.port ? `:${d.port}` : ""}
                      </TableCell>
                      <TableCell>{d.description ?? "—"}</TableCell>
                      <TableCell className="space-x-2">
                        {toDomainProposal(d) && (
                          <Button
                            size="sm"
                            variant="outline"
                            aria-label={`Edit override ${d.description}`}
                            onClick={() => setEditing(d)}
                          >
                            <Pencil className="h-4 w-4" aria-hidden />
                          </Button>
                        )}
                        {d.uuid && (
                          <Button
                            size="sm"
                            variant="outline"
                            aria-label={`Delete override ${d.description ?? d.domain}`}
                            onClick={() => setDeleting(d)}
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

      <Dialog
        open={creating || editable !== null}
        onOpenChange={(o) => !o && close()}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editing
                ? `Change override ${editing.description}`
                : "New domain override"}
            </DialogTitle>
            <DialogDescription>
              Creates a high-risk change request. Nothing is sent to the
              firewall until an admin approves it and applies it.
            </DialogDescription>
          </DialogHeader>
          <DomainForm
            initial={editable ?? undefined}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(override: DomainProposalInput) => {
              if (editing?.uuid)
                stage(() =>
                  api.stageDomainUpdate(
                    firewallId,
                    editing.uuid as string,
                    override,
                  ),
                );
              else stage(() => api.stageDomain(firewallId, override));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this domain override?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete the override{" "}
            <strong>{deleting?.description ?? deleting?.domain}</strong>.
            Nothing is sent to the firewall until an admin approves it and
            applies it by typing the description.
          </>
        }
        onConfirm={() => {
          if (!deleting?.uuid) return;
          const target = deleting;
          stage(() => api.stageDomainDelete(firewallId, target.uuid as string));
        }}
      />
    </>
  );
}
