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
  const key = c.kind === "rule" ? "label" : "name";
  const value = c.proposed?.[key];
  return typeof value === "string" ? value : undefined;
}

export function describeChange(c: ChangeRequest): string {
  if (c.kind === "rule" && c.action === "create") return `create rule ${targetName(c) ?? "?"}`;
  if (c.kind === "rule" && c.action === "toggle") {
    return `${c.proposed?.enabled === false ? "disable" : "enable"} rule ${targetName(c) ?? "?"}`;
  }
  return `${c.action} ${c.kind} ${targetName(c) ?? "?"}`;
}

export function describeEffect(c: ChangeRequest, firewall: string): string {
  const name = targetName(c) ?? "?";
  if (c.kind === "rule" && c.action === "create") {
    return `This creates the rule "${name}" on ${firewall} after the last existing rule and reloads the firewall rules immediately.`;
  }
  if (c.kind === "rule") {
    const verb = c.proposed?.enabled === false ? "disables" : "enables";
    return `This ${verb} the rule "${name}" on ${firewall} and reloads the firewall rules immediately.`;
  }
  if (c.action === "delete") return `This deletes the alias ${name} from ${firewall} and activates the removal immediately.`;
  if (c.action === "update") return `This changes the alias ${name} on ${firewall} and activates it immediately.`;
  return `This creates the alias ${name} on ${firewall} and activates it immediately.`;
}
