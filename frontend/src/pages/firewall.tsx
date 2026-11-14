import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/features/auth/auth";
import { AliasForm } from "@/features/changes/alias-form";
import { RuleForm, toProposal } from "@/features/changes/rule-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { AliasInfo, AliasProposalInput, RuleInfo, RuleProposalInput } from "@/lib/schemas";

const EDITABLE_TYPES = ["host", "network", "port"];

function actionBadge(r: RuleInfo) {
  if (!r.action) return <Badge>—</Badge>;
  return <Badge variant={r.action === "pass" ? "success" : "critical"}>{r.action}</Badge>;
}

function AliasesCard({ firewallId }: { firewallId: string }) {
  const { hasRole } = useAuth();
  const canManage = hasRole("admin", "network_admin");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AliasInfo | null>(null);
  const [deleting, setDeleting] = useState<AliasInfo | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => {
    setEditing(null);
    setDeleting(null);
    setError(null);
  };
  const stage = async (run: () => Promise<{ id: string }>) => {
    setError(null);
    setPending(true);
    try {
      const made = await run();
      await qc.invalidateQueries({ queryKey: ["changes"] });
      close();
      navigate(`/administration/changes/${made.id}`);
    } catch (e) {
      setError(describeError(e).message);
    } finally {
      setPending(false);
    }
  };
  const q = useQuery({
    queryKey: ["firewalls", firewallId, "aliases"],
    queryFn: () => api.firewallAliases(firewallId),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Aliases {q.data && !q.data.registry_verified && <UnverifiedBadge />}
        </CardTitle>
        <CardDescription>List of aliases. Changes go through a reviewed request.</CardDescription>
      </CardHeader>
      <CardContent>
        {q.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">Loading…</p>
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : q.data.aliases.length === 0 ? (
          <p className="text-sm text-muted-foreground">The firewall reported no aliases.</p>
        ) : (
          <>
            {q.data.truncated && (
              <p className="mb-2 text-sm text-muted-foreground">Only the first aliases are shown.</p>
            )}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Content</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Enabled</TableHead>
                  {canManage && <TableHead className="text-right">Change</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {q.data.aliases.map((a, n) => (
                  <TableRow key={`${a.uuid ?? "?"}-${n}`}>
                    <TableCell className="font-medium">{a.name ?? "—"}</TableCell>
                    <TableCell>{a.type ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.content.join(", ") || "—"}
                      {a.content_truncated && " …"}
                    </TableCell>
                    <TableCell>{a.description ?? "—"}</TableCell>
                    <TableCell>{a.enabled === null ? "—" : a.enabled ? "Yes" : "No"}</TableCell>
                    {canManage && (
                      <TableCell className="space-x-1 text-right">
                        {a.uuid && a.name && a.type && EDITABLE_TYPES.includes(a.type) && !a.content_truncated ? (
                          <>
                            <Button size="sm" variant="outline" onClick={() => setEditing(a)}>
                              <Pencil className="h-3 w-3" /> Edit
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => setDeleting(a)}>
                              <Trash2 className="h-3 w-3" /> Delete
                            </Button>
                          </>
                        ) : (
                          <span className="text-xs text-muted-foreground">Not editable here</span>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </>
        )}
      </CardContent>
      <Dialog open={editing !== null} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change alias {editing?.name}</DialogTitle>
            <DialogDescription>
              This creates a change request. Nothing is sent to the firewall until it is reviewed,
              approved and applied. Name and type cannot be changed.
            </DialogDescription>
          </DialogHeader>
          {editing && (
            <AliasForm
              initial={{
                name: editing.name ?? "",
                type: editing.type as AliasProposalInput["type"],
                content: editing.content,
                description: editing.description ?? "",
                enabled: editing.enabled !== false,
              }}
              pending={pending}
              error={error}
              onCancel={close}
              onSubmit={(alias) =>
                void stage(() => api.stageAliasUpdate(firewallId, editing.uuid as string, alias))
              }
            />
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deletion of this alias?"
        destructive
        confirmLabel="Create delete request"
        pending={pending}
        error={error}
        description={
          <>
            This creates a high-risk change request to delete <strong>{deleting?.name}</strong>. An
            administrator must approve it and type the name again to apply it. The firewall refuses to
            delete an alias that is still in use.
          </>
        }
        onConfirm={() => deleting && void stage(() => api.stageAliasDelete(firewallId, deleting.uuid as string))}
      />
    </Card>
  );
}

function endpoint(net: string | null, port: string | null) {
  return [net ?? "any", port].filter(Boolean).join(":");
}

export function FirewallPage() {
  const { hasRole } = useAuth();
  const canManage = hasRole("admin", "network_admin");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [toggling, setToggling] = useState<RuleInfo | null>(null);
  const [togglePending, setTogglePending] = useState(false);
  const [toggleError, setToggleError] = useState<string | null>(null);
  const closeToggle = () => {
    setToggling(null);
    setToggleError(null);
  };
  const [editingRule, setEditingRule] = useState<RuleInfo | null>(null);
  const [deletingRule, setDeletingRule] = useState<RuleInfo | null>(null);
  const [rulePending, setRulePending] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const closeRule = () => {
    setEditingRule(null);
    setDeletingRule(null);
    setRuleError(null);
  };
  const stageEdit = (rule: RuleProposalInput) => {
    if (!editingRule?.uuid || !selected) return;
    setRuleError(null);
    setRulePending(true);
    api
      .stageRuleUpdate(selected, editingRule.uuid, rule)
      .then(async (made) => {
        await qc.invalidateQueries({ queryKey: ["changes"] });
        closeRule();
        navigate(`/administration/changes/${made.id}`);
      })
      .catch((e: unknown) => setRuleError(describeError(e).message))
      .finally(() => setRulePending(false));
  };
  const options = useQuery({ queryKey: ["firewalls", "options"], queryFn: api.listFirewallOptions });
  const [chosen, setChosen] = useState<string | null>(null);
  const firewalls = options.data ?? [];
  const selected = chosen ?? firewalls[0]?.id ?? null;

  const q = useQuery({
    queryKey: ["firewalls", selected, "rules"],
    queryFn: () => api.firewallRules(selected as string),
    enabled: selected !== null,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Firewall</h1>
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
              Rules {q.data && !q.data.registry_verified && <UnverifiedBadge />}
            </CardTitle>
            <CardDescription>List of filter rules. Changes go through a reviewed request.</CardDescription>
          </CardHeader>
          <CardContent>
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">Loading…</p>
            ) : q.isError ? (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ) : q.data.rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">The firewall reported no rules.</p>
            ) : (
              <>
                {q.data.truncated && (
                  <p className="mb-2 text-sm text-muted-foreground">Only the first rules are shown.</p>
                )}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>#</TableHead>
                      <TableHead>Interface</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Direction</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Enabled</TableHead>
                      <TableHead>Log</TableHead>
                      {canManage && <TableHead className="text-right">Change</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {q.data.rules.map((r, n) => (
                      <TableRow key={`${r.uuid ?? "?"}-${n}`}>
                        <TableCell>{r.sequence ?? "—"}</TableCell>
                        <TableCell>{r.interface ?? "—"}</TableCell>
                        <TableCell>{actionBadge(r)}</TableCell>
                        <TableCell>{r.direction ?? "—"}</TableCell>
                        <TableCell>{[r.ip_protocol, r.protocol].filter(Boolean).join(" ") || "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(r.source, r.source_port)}</TableCell>
                        <TableCell className="font-mono text-xs">{endpoint(r.destination, r.destination_port)}</TableCell>
                        <TableCell>{r.description ?? "—"}</TableCell>
                        <TableCell>{r.enabled === null ? "—" : r.enabled ? "Yes" : "No"}</TableCell>
                        <TableCell>{r.log === null ? "—" : r.log ? "Yes" : "No"}</TableCell>
                        {canManage && (
                          <TableCell className="text-right">
                            {r.uuid && r.enabled !== null ? (
                              <div className="flex justify-end gap-1">
                                <Button size="sm" variant="outline" onClick={() => setToggling(r)}>
                                  {r.enabled ? "Disable" : "Enable"}
                                </Button>
                                {toProposal(r) && (
                                  <Button size="sm" variant="outline" onClick={() => setEditingRule(r)}>
                                    <Pencil className="h-3 w-3" /> Edit
                                  </Button>
                                )}
                                {r.sequence !== null && r.description && (
                                  <Button size="sm" variant="outline" onClick={() => setDeletingRule(r)}>
                                    <Trash2 className="h-3 w-3" /> Delete
                                  </Button>
                                )}
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
              </>
            )}
          </CardContent>
        </Card>
      )}
      {selected && <AliasesCard firewallId={selected} />}
      <Dialog open={editingRule !== null} onOpenChange={(o) => !o && closeRule()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change rule {editingRule?.description}</DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it is reviewed, approved and
              applied.
            </DialogDescription>
          </DialogHeader>
          {editingRule && toProposal(editingRule) && (
            <RuleForm
              initial={toProposal(editingRule) as RuleProposalInput}
              pending={rulePending}
              error={ruleError}
              onSubmit={stageEdit}
              onCancel={closeRule}
            />
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deletingRule !== null}
        onOpenChange={(o) => !o && closeRule()}
        title="Request deleting this rule?"
        confirmLabel="Create change request"
        destructive
        pending={rulePending}
        error={ruleError}
        description={
          <>
            This creates a high-risk change request to delete the rule{" "}
            <strong>{deletingRule?.description}</strong>. Nothing is sent to the firewall until an admin
            approves it and applies it by typing the rule description.
          </>
        }
        onConfirm={() => {
          if (!deletingRule?.uuid || !selected) return;
          setRuleError(null);
          setRulePending(true);
          api
            .stageRuleDelete(selected, deletingRule.uuid)
            .then(async (made) => {
              await qc.invalidateQueries({ queryKey: ["changes"] });
              closeRule();
              navigate(`/administration/changes/${made.id}`);
            })
            .catch((e: unknown) => setRuleError(describeError(e).message))
            .finally(() => setRulePending(false));
        }}
      />
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(o) => !o && closeToggle()}
        title={toggling?.enabled ? "Request disabling this rule?" : "Request enabling this rule?"}
        confirmLabel="Create change request"
        pending={togglePending}
        error={toggleError}
        description={
          <>
            This creates a change request for the rule{" "}
            <strong>{toggling?.description ?? toggling?.uuid?.slice(0, 8)}</strong>. Nothing is sent to the
            firewall until it is reviewed, approved and applied. Rules on WAN, pass-any rules and
            system rules are marked high risk.
          </>
        }
        onConfirm={() => {
          if (!toggling?.uuid || !selected) return;
          setToggleError(null);
          setTogglePending(true);
          api
            .stageRuleToggle(selected, toggling.uuid, !toggling.enabled)
            .then(async (made) => {
              await qc.invalidateQueries({ queryKey: ["changes"] });
              closeToggle();
              navigate(`/administration/changes/${made.id}`);
            })
            .catch((e: unknown) => setToggleError(describeError(e).message))
            .finally(() => setTogglePending(false));
        }}
      />
    </div>
  );
}
