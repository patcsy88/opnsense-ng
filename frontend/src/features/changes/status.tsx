import { Badge } from "@/components/ui/badge";
import type { ChangeRequest } from "@/lib/schemas";

const LABELS: Record<string, string> = {
  draft: "Draft",
  validated: "Ready to submit",
  in_review: "In review",
  approved: "Approved",
  applying: "Applying",
  applied: "Applied",
  rejected: "Rejected",
  cancelled: "Cancelled",
  failed: "Failed",
  stale: "Stale",
};

const VARIANTS: Record<string, "default" | "success" | "warning" | "critical"> = {
  applied: "success",
  approved: "warning",
  applying: "warning",
  failed: "critical",
  stale: "critical",
  rejected: "critical",
};

export function statusLabel(status: string): string {
  return LABELS[status] ?? status;
}

export function ChangeStatusBadge({ status }: { status: string }) {
  return <Badge variant={VARIANTS[status] ?? "default"}>{statusLabel(status)}</Badge>;
}

export function targetName(c: ChangeRequest): string | undefined {
  const key = c.kind === "rule" || c.kind === "nat_forward" || c.kind === "dnsmasq_host" || c.kind === "dnsmasq_domain" ? "label" : "name";
  const value = c.proposed?.[key];
  return typeof value === "string" ? value : undefined;
}

export function describeChange(c: ChangeRequest): string {
  if (c.kind === "dnsmasq_domain") return `${c.action} DNS domain override ${targetName(c) ?? "?"}`;
  if (c.kind === "dnsmasq_host") return `${c.action} DNS/DHCP host ${targetName(c) ?? "?"}`;
  if (c.kind === "nat_forward") {
    const name = targetName(c) ?? "?";
    if (c.action === "toggle") return `${c.proposed?.enabled === false ? "disable" : "enable"} port forward ${name}`;
    return `${c.action} port forward ${name}`;
  }
  if (c.kind === "rule" && c.action === "create") return `create rule ${targetName(c) ?? "?"}`;
  if (c.kind === "rule" && (c.action === "update" || c.action === "delete")) {
    return `${c.action} rule ${targetName(c) ?? "?"}`;
  }
  if (c.kind === "rule" && c.action === "toggle") {
    return `${c.proposed?.enabled === false ? "disable" : "enable"} rule ${targetName(c) ?? "?"}`;
  }
  return `${c.action} ${c.kind} ${targetName(c) ?? "?"}`;
}

export function describeEffect(c: ChangeRequest, firewall: string): string {
  const name = targetName(c) ?? "?";
  if (c.kind === "dnsmasq_domain") {
    const verb = c.action === "create" ? "creates" : c.action === "update" ? "changes" : "deletes";
    return `This ${verb} the domain override "${name}" on ${firewall} and restarts Dnsmasq. It decides which DNS server answers for that domain, and DNS and DHCP pause for a moment.`;
  }
  if (c.kind === "dnsmasq_host") {
    const verb = c.action === "create" ? "creates" : c.action === "update" ? "changes" : "deletes";
    return `This ${verb} the static host "${name}" on ${firewall} and restarts Dnsmasq. DNS and DHCP pause for a moment; existing DHCP leases are kept.`;
  }
  if (c.kind === "nat_forward") {
    const tail = "and reloads the firewall rules immediately. It does not add a pass rule.";
    if (c.action === "create") return `This creates the port forward "${name}" on ${firewall} ${tail}`;
    if (c.action === "update") return `This changes the port forward "${name}" on ${firewall} ${tail}`;
    if (c.action === "delete") return `This permanently deletes the port forward "${name}" from ${firewall} ${tail}`;
    const verb = c.proposed?.enabled === false ? "disables" : "enables";
    return `This ${verb} the port forward "${name}" on ${firewall} ${tail}`;
  }
  if (c.kind === "rule" && c.action === "create") {
    return `This creates the rule "${name}" on ${firewall} after the last existing rule and reloads the firewall rules immediately.`;
  }
  if (c.kind === "rule" && c.action === "update") {
    return `This changes the rule "${name}" on ${firewall} and reloads the firewall rules immediately. Its position is unchanged.`;
  }
  if (c.kind === "rule" && c.action === "delete") {
    return `This permanently deletes the rule "${name}" from ${firewall} and reloads the firewall rules immediately.`;
  }
  if (c.kind === "rule") {
    const verb = c.proposed?.enabled === false ? "disables" : "enables";
    return `This ${verb} the rule "${name}" on ${firewall} and reloads the firewall rules immediately.`;
  }
  if (c.action === "delete") return `This deletes the alias ${name} from ${firewall} and activates the removal immediately.`;
  if (c.action === "update") return `This changes the alias ${name} on ${firewall} and activates it immediately.`;
  return `This creates the alias ${name} on ${firewall} and activates it immediately.`;
}
