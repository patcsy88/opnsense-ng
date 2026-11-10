import type { Connectivity, SystemStatus } from "@/lib/schemas";
import type { HealthLevel } from "@/components/ui/status-badge";

export function connectivityLevel(c: Connectivity): HealthLevel {
  return c.ok ? "healthy" : "critical";
}

/** The normalised schema carries no CPU/memory/disk figures, so health is judged on completeness. */
export function systemLevel(s: SystemStatus): HealthLevel {
  if (!s.hostname && s.versions.length === 0 && !s.uptime) return "critical";
  if (!s.hostname || !s.uptime || s.versions.length === 0) return "warning";
  return "healthy";
}
