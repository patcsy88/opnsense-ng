import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/features/auth/auth";
import { AliasForm } from "@/features/changes/alias-form";
import { RuleForm } from "@/features/changes/rule-form";
import { ChangeStatusBadge, describeChange, statusLabel } from "@/features/changes/status";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { CHANGE_STATUSES, type AliasProposalInput, type RuleProposalInput } from "@/lib/schemas";

export function ChangesPage() {
  const { hasRole } = useAuth();
  const canManage = hasRole("admin", "network_admin");
  const qc = useQueryClient();
  const navigate = useNavigate();
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [creating, setCreating] = useState<"alias" | "rule" | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;
  const names = new Map(firewalls.map((f) => [f.id, f.name]));

  const list = useQuery({
    queryKey: ["changes", selected, status],
    queryFn: () => api.listChanges({ firewallId: selected ?? undefined, status: status || undefined }),
    enabled: selected !== null,
  });

  const create = async (input: AliasProposalInput | RuleProposalInput) => {
    if (!selected) return;
    setFormError(null);
    setSaving(true);
    try {
      const made =
        creating === "rule"
          ? await api.stageRule(selected, input as RuleProposalInput)
          : await api.stageAlias(selected, input as AliasProposalInput);
      await qc.invalidateQueries({ queryKey: ["changes"] });
      setCreating(null);
      navigate(`/changes/${made.id}`);
    } catch (e) {
      setFormError(describeError(e).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Changes</h1>
        <div className="flex flex-wrap items-center gap-3">
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
          <label className="flex items-center gap-2 text-sm">
            Status
            <select
              className="h-9 rounded-md border border-border bg-card px-2"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All</option>
              {CHANGE_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {statusLabel(s)}
                </option>
              ))}
            </select>
          </label>
          {canManage && (
            <>
              <Button onClick={() => setCreating("alias")} disabled={selected === null}>
                <Plus className="h-4 w-4" /> New alias
              </Button>
              <Button variant="outline" onClick={() => setCreating("rule")} disabled={selected === null}>
                <Plus className="h-4 w-4" /> New rule
              </Button>
            </>
          )}
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        Changes are staged, reviewed and then applied by an administrator. There is no automatic
        rollback: to undo an applied change, create a new request.
      </p>

      {options.isError && <ErrorState error={options.error} onRetry={() => void options.refetch()} />}
      {options.isSuccess && firewalls.length === 0 && (
        <Card>
          <CardContent className="pt-4 text-sm">No firewalls configured.</CardContent>
        </Card>
      )}

      {selected && (
        <Card>
          <CardContent className="pt-4">
            {list.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : list.isError ? (
              <ErrorState error={list.error} onRetry={() => void list.refetch()} />
            ) : list.data.length === 0 ? (
              <p className="text-sm text-muted-foreground">No change requests.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Change</TableHead>
                    <TableHead>Firewall</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Requested by</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.data.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell className="font-medium">
                        <Link className="text-primary underline" to={`/changes/${c.id}`}>
                          {describeChange(c)}
                        </Link>
                      </TableCell>
                      <TableCell>{names.get(c.firewall_id) ?? "—"}</TableCell>
                      <TableCell>
                        <ChangeStatusBadge status={c.status} />
                      </TableCell>
                      <TableCell>{c.requester_username}</TableCell>
                      <TableCell>{new Date(c.created_at).toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog
        open={creating !== null}
        onOpenChange={(o) => {
          if (!o) {
            setCreating(null);
            setFormError(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{creating === "rule" ? "New rule" : "New alias"}</DialogTitle>
            <DialogDescription>
              {creating === "rule"
                ? "Propose a new firewall rule for "
                : "Propose a new host, network or port alias for "}
              {selected ? names.get(selected) : "the firewall"}. Nothing is sent until it is reviewed, approved and
              applied.
            </DialogDescription>
          </DialogHeader>
          {creating === "rule" ? (
            <RuleForm
              pending={saving}
              error={formError}
              onSubmit={(r) => void create(r)}
              onCancel={() => {
                setCreating(null);
                setFormError(null);
              }}
            />
          ) : (
            <AliasForm
              pending={saving}
              error={formError}
              onSubmit={(a) => void create(a)}
              onCancel={() => {
                setCreating(null);
                setFormError(null);
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
