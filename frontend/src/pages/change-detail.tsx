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
import { ChangeStatusBadge, describeChange, describeEffect, statusLabel, targetName } from "@/features/changes/status";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { ChangeDetail } from "@/lib/schemas";

type Verb = "submit" | "approve" | "reject" | "cancel";
const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

const RULE_FIELDS: [string, string][] = [
  ["Interface", "interface"],
  ["Action", "action"],
  ["Direction", "direction"],
  ["Protocol", "protocol"],
  ["Source", "source"],
  ["Source port", "source_port"],
  ["Destination", "destination"],
  ["Destination port", "destination_port"],
  ["Sequence", "sequence"],
];

function ruleRows(snapshot: Record<string, unknown>): [string, string][] {
  const rows: [string, string][] = RULE_FIELDS.map(([label, key]) => [label, String(snapshot[key] ?? "") || "—"]);
  rows.push(["Enabled", snapshot.enabled === false ? "No" : "Yes"]);
  return rows;
}

const risk = (p: Record<string, unknown>): [string, string][] =>
  Array.isArray(p.risk) && p.risk.length > 0 ? [["High risk because", p.risk.map(String).join("; ")]] : [];

function forwardRows(p: Record<string, unknown>): [string, string][] {
  if (p.interface === undefined) {
    if (p.enabled === undefined) return [["Port forward", String(p.label ?? "—")], ...risk(p)];
    return [
      ["Port forward", String(p.label ?? "—")],
      ["New state", p.enabled === false ? "Disabled" : "Enabled"],
      ...risk(p),
    ];
  }
  const ports = (v: unknown) => (v ? `:${String(v)}` : "");
  return [
    ["Description", String(p.description ?? "—")],
    ["Interface", `${String(p.interface)} (${p.ip_protocol === "inet6" ? "IPv6" : "IPv4"})`],
    ["Protocol", String(p.protocol)],
    ["Source", `${String(p.source)}${ports(p.source_port)}`],
    ["Destination", `${String(p.destination)}${ports(p.destination_port)}`],
    ["Redirect to", `${String(p.target)}${ports(p.target_port)}`],
    ["Log", p.log ? "Yes" : "No"],
    ["Enabled", p.enabled === false ? "No" : "Yes"],
    ...risk(p),
  ];
}

function currentForwardRows(s: Record<string, unknown>): [string, string][] {
  const ports = (v: unknown) => (v ? `:${String(v)}` : "");
  return [
    ["Interface", String(s.interface ?? "—")],
    ["Protocol", String(s.protocol ?? "—")],
    ["Source", `${String(s.source ?? "any")}${ports(s.source_port)}`],
    ["Destination", `${String(s.destination ?? "—")}${ports(s.destination_port)}`],
    ["Redirect to", `${String(s.target ?? "—")}${ports(s.target_port)}`],
    ["Sequence", String(s.sequence ?? "—")],
    ["Enabled", s.enabled === false ? "No" : "Yes"],
  ];
}

const list = (v: unknown) => (Array.isArray(v) && v.length > 0 ? v.map(String).join(", ") : "—");

function hostRows(p: Record<string, unknown>): [string, string][] {
  if (p.ips === undefined) {
    return [["Host entry", String(p.label ?? "—")], ...risk(p)];
  }
  return [
    ["Description", String(p.description ?? "—")],
    ["Name", `${String(p.host)}${p.domain ? `.${String(p.domain)}` : ""}`],
    ["IP addresses", list(p.ips)],
    ...(p.hwaddrs === undefined ? [] : ([["MAC addresses", list(p.hwaddrs)]] as [string, string][])),
    ["Aliases", list(p.cnames)],
    ["Ignore (block DHCP)", p.ignore ? "Yes" : "No"],
    ...risk(p),
  ];
}

function currentHostRows(s: Record<string, unknown>): [string, string][] {
  return [
    ["Name", `${String(s.host ?? "—")}${s.domain ? `.${String(s.domain)}` : ""}`],
    ["IP addresses", list(s.ips)],
    ...(s.hwaddrs === undefined ? [] : ([["MAC addresses", list(s.hwaddrs)]] as [string, string][])),
    ["Aliases", list(s.cnames)],
    ["Ignore (block DHCP)", s.ignore ? "Yes" : "No"],
    ["Description", String(s.description ?? "—")],
  ];
}

function domainRows(p: Record<string, unknown>): [string, string][] {
  if (p.server === undefined) return [["Domain override", String(p.label ?? "—")], ...risk(p)];
  return [
    ["Description", String(p.description ?? "—")],
    ["Domain", String(p.domain)],
    ["DNS server", `${String(p.server)}${p.port ? `:${String(p.port)}` : ""}`],
    ...risk(p),
  ];
}

function currentDomainRows(s: Record<string, unknown>): [string, string][] {
  return [
    ["Domain", String(s.domain ?? "—")],
    ["DNS server", `${String(s.server ?? "—")}${s.port ? `:${String(s.port)}` : ""}`],
    ["Description", String(s.description ?? "—")],
  ];
}

function unboundHostRows(p: Record<string, unknown>): [string, string][] {
  const name = `${String(p.hostname)}${p.domain ? `.${String(p.domain)}` : ""}`;
  if (p.server === undefined) {
    return [
      ["Host override", String(p.label ?? "—")],
      ...(p.enabled === undefined ? [] : ([["Enabled", p.enabled ? "Yes" : "No"]] as [string, string][])),
      ...(p.hostname === undefined ? [] : ([["Name", name]] as [string, string][])),
      ...risk(p),
    ];
  }
  return [
    ["Description", String(p.description ?? "—")],
    ["Name", name],
    ["Record", `${String(p.rr)} ${String(p.server)}${p.ttl ? ` (TTL ${String(p.ttl)})` : ""}`],
    ["Enabled", p.enabled === false ? "No" : "Yes"],
    ...risk(p),
  ];
}

function currentUnboundHostRows(s: Record<string, unknown>): [string, string][] {
  return [
    ["Name", `${String(s.hostname ?? "—")}${s.domain ? `.${String(s.domain)}` : ""}`],
    ["Record", `${String(s.rr ?? "—")} ${String(s.server ?? "—")}`],
    ["Enabled", s.enabled === false ? "No" : "Yes"],
    ["Description", String(s.description ?? "—")],
  ];
}

function proposalRows(source: Record<string, unknown> | null, kind = "alias"): [string, string][] {
  const p = source ?? {};
  if (kind === "dnsmasq_host") return hostRows(p);
  if (kind === "dnsmasq_domain") return domainRows(p);
  if (kind === "unbound_host") return unboundHostRows(p);
  if (kind === "nat_forward") return forwardRows(p);
  if (kind === "rule" && p.action !== undefined) {
    const ports = (v: unknown) => (v ? `:${String(v)}` : "");
    return [
      ["Description", String(p.description ?? "—")],
      ["Action", String(p.action)],
      ["Interface", `${String(p.interface)} (${String(p.direction)}, ${p.ip_protocol === "inet6" ? "IPv6" : "IPv4"})`],
      ["Protocol", String(p.protocol)],
      ["Source", `${String(p.source)}${ports(p.source_port)}`],
      ["Destination", `${String(p.destination)}${ports(p.destination_port)}`],
      ["Log", p.log ? "Yes" : "No"],
      ["Enabled", p.enabled === false ? "No" : "Yes"],
      ...(Array.isArray(p.risk) && p.risk.length > 0 ? ([["High risk because", p.risk.join("; ")]] as [string, string][]) : []),
    ];
  }
  if (kind === "rule" && p.action === undefined && p.enabled === undefined) {
    return [
      ["Rule", String(p.label ?? "—")],
      ...(Array.isArray(p.risk) && p.risk.length > 0 ? ([["High risk because", p.risk.join("; ")]] as [string, string][]) : []),
    ];
  }
  if (kind === "rule") {
    return [
      ["Rule", String(p.label ?? "—")],
      ["New state", p.enabled === false ? "Disabled" : "Enabled"],
    ];
  }
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
  const aliasName = targetName(c);
  const busy = move.isPending || apply.isPending;

  const canSubmit = c.status === "validated" && manage && (own || isAdmin);
  const canReview = c.status === "in_review" && manage && (!own || isAdmin) && (!c.high_risk || isAdmin);
  const canCancel = OPEN.has(c.status) && manage && (own || isAdmin);
  const canApply = c.status === "approved" && isAdmin;
  const error = move.isError ? describeError(move.error).message : null;

  return (
    <div className="space-y-4">
      <p className="text-sm">
        <Link className="text-primary underline" to="/administration/changes">
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
          <CardTitle>{c.action === "delete" ? `${c.kind === "rule" ? "Rule" : c.kind === "nat_forward" ? "Port forward" : c.kind === "dnsmasq_host" ? "Host entry" : c.kind === "dnsmasq_domain" ? "Domain override" : c.kind === "unbound_host" ? "Host override" : "Alias"} to delete` : "Proposal"}</CardTitle>
          <CardDescription>
            Firewall: {firewall} · requested by {c.requester_username}
            {c.reviewer_username ? ` · reviewed by ${c.reviewer_username}` : ""}
            {c.applier_username ? ` · applied by ${c.applier_username}` : ""}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
            {proposalRows(c.proposed, c.kind).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{k}</dt>
                <dd className="whitespace-pre-wrap break-all font-mono text-xs sm:text-sm">{v}</dd>
              </div>
            ))}
          </dl>
          {c.action === "delete" && (
            <p className="mt-3 text-sm font-medium text-destructive">
              {c.kind === "rule"
                ? "This rule will be deleted. See the current rule below."
                : c.kind === "nat_forward"
                  ? "This port forward will be deleted. See the current forward below."
                  : c.kind === "dnsmasq_host"
                    ? "This host entry will be deleted. See the current entry below."
                    : c.kind === "dnsmasq_domain"
                    ? "This domain override will be deleted. See the current override below."
                    : c.kind === "unbound_host"
                    ? "This host override will be deleted. See the current override below."
                    : "This alias will be deleted. The values above are what it holds now."}
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

      {c.kind === "rule" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Current rule</CardTitle>
            <CardDescription>
              The rule as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {ruleRows(c.base_snapshot).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {c.kind === "unbound_host" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Current host override</CardTitle>
            <CardDescription>
              The override as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {currentUnboundHostRows(c.base_snapshot).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {c.kind === "dnsmasq_domain" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Current domain override</CardTitle>
            <CardDescription>
              The override as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {currentDomainRows(c.base_snapshot).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {c.kind === "dnsmasq_host" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Current host entry</CardTitle>
            <CardDescription>
              The entry as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {currentHostRows(c.base_snapshot).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {c.kind === "nat_forward" && c.base_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Current port forward</CardTitle>
            <CardDescription>
              The forward as it was when the request was made. Applying is refused if it has changed since.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2 text-sm sm:grid-cols-[8rem_1fr]">
              {currentForwardRows(c.base_snapshot).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all font-mono text-xs sm:text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {c.kind === "alias" && c.action === "update" && c.base_snapshot && (
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
