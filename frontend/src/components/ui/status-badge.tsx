import { AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { Badge } from "./badge";

export type HealthLevel = "healthy" | "warning" | "critical";

const CONFIG = {
  healthy: { variant: "success", Icon: CheckCircle2, label: "Healthy" },
  warning: { variant: "warning", Icon: AlertTriangle, label: "Warning" },
  critical: { variant: "critical", Icon: XCircle, label: "Critical" },
} as const;

/** Colour is never the only signal: each level has its own icon and text. */
export function StatusBadge({ level, label }: { level: HealthLevel; label?: string }) {
  const { variant, Icon, label: defaultLabel } = CONFIG[level];
  return (
    <Badge variant={variant}>
      <Icon className="h-3 w-3" aria-hidden />
      {label ?? defaultLabel}
    </Badge>
  );
}

export function UnverifiedBadge() {
  return (
    <Badge variant="warning" title="This API mapping has not been verified against a live OPNsense instance">
      <AlertTriangle className="h-3 w-3" aria-hidden />
      Unverified API mapping
    </Badge>
  );
}
