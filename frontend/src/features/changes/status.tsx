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

export function describeChange(c: ChangeRequest): string {
  const name = typeof c.proposed?.name === "string" ? c.proposed.name : "?";
  return `${c.action} ${c.kind} ${name}`;
}
