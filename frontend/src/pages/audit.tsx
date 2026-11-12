import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/features/auth/auth";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { AuditEntry } from "@/lib/schemas";

const OUTCOMES = ["", "success", "failure", "denied"] as const;

interface Filters {
  username: string;
  action: string;
  outcome: string;
  since: string;
  until: string;
}

const EMPTY: Filters = { username: "", action: "", outcome: "", since: "", until: "" };

function outcomeVariant(outcome: string) {
  if (outcome === "success") return "success" as const;
  if (outcome === "denied") return "warning" as const;
  return "critical" as const;
}

function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function AuditPage() {
  const { hasRole } = useAuth();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const [purgeOpen, setPurgeOpen] = useState(false);

  const q = useQuery({
    queryKey: ["audit", applied, page],
    queryFn: () =>
      api.listAudit({
        username: applied.username.trim() || undefined,
        action: applied.action.trim() || undefined,
        outcome: applied.outcome || undefined,
        since: toIso(applied.since),
        until: toIso(applied.until),
        page,
      }),
    placeholderData: (previous) => previous,
  });

  const purge = useMutation({
    mutationFn: () => api.purgeAudit(),
    onSuccess: async () => {
      setPurgeOpen(false);
      setPage(1);
      await qc.invalidateQueries({ queryKey: ["audit"] });
    },
  });

  const data = q.data;
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  const canPurge = hasRole("admin");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <Link className="text-sm text-primary underline" to="/administration">
          Back to Administration
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>Newest first. Viewing the log is recorded too.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
            onSubmit={(e) => {
              e.preventDefault();
              setPage(1);
              setApplied(draft);
            }}
          >
            <label className="space-y-1 text-sm">
              User
              <Input value={draft.username} onChange={(e) => setDraft({ ...draft, username: e.target.value })} />
            </label>
            <label className="space-y-1 text-sm">
              Action starts with
              <Input
                value={draft.action}
                placeholder="e.g. firewall. or change."
                onChange={(e) => setDraft({ ...draft, action: e.target.value })}
              />
            </label>
            <label className="space-y-1 text-sm">
              Outcome
              <select
                className="h-9 w-full rounded-md border border-border bg-card px-2"
                value={draft.outcome}
                onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}
              >
                {OUTCOMES.map((o) => (
                  <option key={o} value={o}>
                    {o === "" ? "Any" : o}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-sm">
              From
              <Input
                type="datetime-local"
                value={draft.since}
                onChange={(e) => setDraft({ ...draft, since: e.target.value })}
              />
            </label>
            <label className="space-y-1 text-sm">
              To
              <Input
                type="datetime-local"
                value={draft.until}
                onChange={(e) => setDraft({ ...draft, until: e.target.value })}
              />
            </label>
            <div className="flex items-end gap-2">
              <Button type="submit">Apply filters</Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setDraft(EMPTY);
                  setApplied(EMPTY);
                  setPage(1);
                }}
              >
                Clear
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}

      {!q.isError && (
        <Card>
          <CardHeader>
            <CardTitle>Records</CardTitle>
            <CardDescription>
              {data ? `${data.total.toLocaleString()} records. Retention is ${data.retention_days} days.` : "Loading…"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading…
              </p>
            ) : data && data.items.length === 0 ? (
              <p className="text-sm text-muted-foreground">No records match.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Source IP</TableHead>
                    <TableHead>
                      <span className="sr-only">Details</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data?.items.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell>{new Date(e.timestamp).toLocaleString()}</TableCell>
                      <TableCell>{e.username ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs sm:text-sm">{e.action}</TableCell>
                      <TableCell>
                        <Badge variant={outcomeVariant(e.outcome)}>{e.outcome}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs sm:text-sm">{e.source_ip ?? "—"}</TableCell>
                      <TableCell>
                        <Button variant="outline" size="sm" onClick={() => setSelected(e)}>
                          Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {data && data.total > 0 && (
              <div className="flex items-center justify-between text-sm">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                  Previous
                </Button>
                <span>
                  Page {data.page} of {pages}
                </span>
                <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>
                  Next
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {canPurge && data && (
        <Card>
          <CardHeader>
            <CardTitle>Purge old records</CardTitle>
            <CardDescription>
              Only records older than {data.retention_days} days can be removed. The purge is itself recorded.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-3">
            <span className="text-sm">{data.purgeable.toLocaleString()} records can be purged.</span>
            <Button variant="destructive" disabled={data.purgeable === 0} onClick={() => setPurgeOpen(true)}>
              Purge old records
            </Button>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={purgeOpen}
        onOpenChange={(o) => {
          setPurgeOpen(o);
          if (!o) purge.reset();
        }}
        title="Purge old audit records?"
        destructive
        confirmLabel="Purge"
        requireText="PURGE"
        pending={purge.isPending}
        error={purge.isError ? describeError(purge.error).message : null}
        description={
          <>
            This permanently deletes <strong>{data?.purgeable.toLocaleString()}</strong> records older than{" "}
            {data?.retention_days} days. It cannot be undone.
          </>
        }
        onConfirm={() => purge.mutate()}
      />

      <Dialog open={selected !== null} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{selected?.action}</DialogTitle>
            <DialogDescription>{selected ? new Date(selected.timestamp).toLocaleString() : ""}</DialogDescription>
          </DialogHeader>
          {selected && (
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-muted-foreground">User</dt>
              <dd>{selected.username ?? "—"}</dd>
              <dt className="text-muted-foreground">Outcome</dt>
              <dd>{selected.outcome}</dd>
              <dt className="text-muted-foreground">Firewall id</dt>
              <dd className="break-all font-mono text-xs">{selected.firewall_id ?? "—"}</dd>
              <dt className="text-muted-foreground">Source IP</dt>
              <dd className="font-mono text-xs">{selected.source_ip ?? "—"}</dd>
              <dt className="text-muted-foreground">User agent</dt>
              <dd className="break-all text-xs">{selected.user_agent ?? "—"}</dd>
              {Object.entries(selected.detail).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all">{v === null ? "—" : String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
