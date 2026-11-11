import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/features/auth/auth";
import { ChangeStatusBadge, describeChange, describeEffect, statusLabel } from "@/features/changes/status";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { ChangeDetail } from "@/lib/schemas";

type Verb = "submit" | "approve" | "reject" | "cancel";
const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

function proposalRows(source: Record<string, unknown> | null): [string, string][] {
  const p = source ?? {};
  const content = Array.isArray(p.content) ? p.content.map(String).join("\n") : "";
  return [
    ["Name", String(p.name ?? "—")],
    ["Type", String(p.type ?? "—")],
    ["Content", content || "—"],
    ["Description", String(p.description ?? "") || "—"],
    ["Enabled", p.enabled === false ? "No" : "Yes"],
  ];
}

export function ChangeDetailPage() {
  const { id = "" } = useParams();
  const { user, hasRole } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["changes", "detail", id], queryFn: () => api.getChange(id) });
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [applyOpen, setApplyOpen] = useState(false);

  const refresh = async (data: ChangeDetail) => {
    qc.setQueryData(["changes", "detail", id], data);
    await qc.invalidateQueries({ queryKey: ["changes"] });
  };
  const move = useMutation({
    mutationFn: (verb: Verb) => api.moveChange(id, verb),
    onSuccess: refresh,
  });
  const apply = useMutation({
    mutationFn: (confirmName?: string) => api.applyChange(id, confirmName),
    onSuccess: async (data) => {
      setApplyOpen(false);
      await refresh(data);
    },
  });

  if (q.isPending) return <p role="status" className="text-sm text-muted-foreground">Loading…</p>;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  const c = q.data;
  const isAdmin = hasRole("admin");
  const manage = hasRole("admin", "network_admin");
  const own = user?.username === c.requester_username;
  const firewall = options.data?.find((f) => f.id === c.firewall_id)?.name ?? "—";
  const aliasName = typeof c.proposed?.name === "string" ? c.proposed.name : undefined;
  const busy = move.isPending || apply.isPending;

  const canSubmit = c.status === "validated" && manage && (own || isAdmin);
  const canReview = c.status === "in_review" && manage && (!own || isAdmin) && (!c.high_risk || isAdmin);
  const canCancel = OPEN.has(c.status) && manage && (own || isAdmin);
  const canApply = c.status === "approved" && isAdmin;
  const error = move.isError ? describeError(move.error).message : null;

  return (
    <div className="space-y-4">
      <p className="text-sm">
        <Link className="text-primary underline" to="/changes">
          ← All changes
        </Link>
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold">{describeChange(c)}</h1>
        <ChangeStatusBadge status={c.status} />
        {c.high_risk && <Badge variant="critical">High risk</Badge>}
        {c.self_approved && <Badge variant="warning">Self-approved</Badge>}
      </div>

      {(c.status === "failed" || c.status === "stale") && c.failure_message && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {c.failure_message}
        </p>
      )}
      {c.status === "applied" && (
        <p role="status" className="rounded-md border border-success/40 bg-success/10 p-3 text-sm text-success">
          Applied to the firewall. To undo, create a new change request.
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{c.action === "delete" ? "Alias to delete" : "Proposal"}</CardTitle>
          <CardDescription>
            Firewall: {firewall} · requested by {c.requester_username}
            {c.reviewer_username ? ` · reviewed by ${c.reviewer_username}` : ""}
            {c.applier_username ? ` · applied by ${c.applier_username}` : ""}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
            {proposalRows(c.proposed).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{k}</dt>
                <dd className="whitespace-pre-wrap break-all font-mono text-xs sm:text-sm">{v}</dd>
              </div>
            ))}
          </dl>
          {c.action === "delete" && (
            <p className="mt-3 text-sm font-medium text-destructive">
              This alias will be deleted. The values above are what it holds now.
            </p>
          )}
        </CardContent>
      </Card>

      {(canSubmit || canReview || canCancel || canApply) && (
        <Card>
          <CardHeader>
            <CardTitle>Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {canSubmit && (
                <Button disabled={busy} onClick={() => move.mutate("submit")}>
                  Submit for review
                </Button>
              )}
              {canReview && (
                <>
                  <Button disabled={busy} onClick={() => move.mutate("approve")}>
                    Approve
                  </Button>
                  <Button variant="outline" disabled={busy} onClick={() => move.mutate("reject")}>
                    Reject
                  </Button>
                </>
              )}
              {canApply && (
                <Button variant="destructive" disabled={busy} onClick={() => setApplyOpen(true)}>
                  Apply to firewall…
                </Button>
              )}
              {canCancel && (
                <Button variant="ghost" disabled={busy} onClick={() => move.mutate("cancel")}>
                  Cancel request
                </Button>
              )}
            </div>
            {c.status === "in_review" && own && !isAdmin && (
              <p className="text-sm text-muted-foreground">
                You cannot approve your own request. Another administrator must review it.
              </p>
            )}
            {c.status === "in_review" && c.high_risk && !isAdmin && (
              <p className="text-sm text-muted-foreground">A high-risk change must be approved by an admin.</p>
            )}
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {c.action === "update" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Before this change</CardTitle>
            <CardDescription>
              The alias as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {proposalRows({
                ...c.base_snapshot,
                enabled: c.base_snapshot.enabled !== false,
              }).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="whitespace-pre-wrap break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>History</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Who</TableHead>
                <TableHead>Change</TableHead>
                <TableHead>Note</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {c.events.map((e, n) => (
                <TableRow key={`${e.timestamp}-${n}`}>
                  <TableCell>{new Date(e.timestamp).toLocaleString()}</TableCell>
                  <TableCell>{e.actor_username}</TableCell>
                  <TableCell>
                    {e.from_status ? `${statusLabel(e.from_status)} → ` : ""}
                    {statusLabel(e.to_status)}
                  </TableCell>
                  <TableCell>{e.note ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={applyOpen}
        onOpenChange={(o) => {
          if (!o) {
            setApplyOpen(false);
            apply.reset();
          }
        }}
        title="Apply this change to the firewall?"
        destructive
        confirmLabel="Apply now"
        requireText={c.high_risk ? aliasName : undefined}
        pending={apply.isPending}
        error={apply.isError ? describeError(apply.error).message : null}
        description={
          <>
            <p>{describeEffect(c, firewall)}</p>
            <p className="mt-2 font-medium">
              There is no automatic rollback. If you need to undo it, you must create and approve a new
              change request.
            </p>
          </>
        }
        onConfirm={() => apply.mutate(c.high_risk ? aliasName : undefined)}
      />
    </div>
  );
}
