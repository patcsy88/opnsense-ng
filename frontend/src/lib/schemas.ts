// Zod schemas mirroring backend/app/auth/schemas.py and backend/app/api/schemas.py.
import { z } from "zod";

export const ROLES = ["admin", "network_admin", "security_admin", "read_only"] as const;
export const roleSchema = z.enum(ROLES);
export type Role = z.infer<typeof roleSchema>;

export const userSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  role: roleSchema,
});
export type User = z.infer<typeof userSchema>;

export const loginResponseSchema = z.object({ user: userSchema, csrf_token: z.string() });
export const logoutAllResponseSchema = z.object({ revoked: z.number().int() });

export const firewallSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  base_url: z.string(),
  verify_tls: z.boolean(),
  has_ca_bundle: z.boolean(),
  allow_writes: z.boolean(),
  created_at: z.string(),
});
export type Firewall = z.infer<typeof firewallSchema>;
export const firewallListSchema = z.array(firewallSchema);

// Selector entries available to every role (no URL or TLS details).
export const firewallOptionSchema = z.object({ id: z.uuid(), name: z.string() });
export const firewallOptionListSchema = z.array(firewallOptionSchema);
export type FirewallOption = z.infer<typeof firewallOptionSchema>;

// `status` is a detailed ConnectionStatus for admins, "reachable"/"unreachable" for others.
export const connectivitySchema = z.object({
  firewall_id: z.uuid(),
  ok: z.boolean(),
  status: z.string(),
  message: z.string(),
  registry_verified: z.boolean(),
});
export type Connectivity = z.infer<typeof connectivitySchema>;

export const systemStatusSchema = z.object({
  hostname: z.string().nullable(),
  versions: z.array(z.string()),
  updates: z.string().nullable(),
  server_time: z.string().nullable(),
  uptime: z.string().nullable(),
  load_average: z.string().nullable(),
  memory_total_bytes: z.number().nullable(),
  memory_used_bytes: z.number().nullable(),
  memory_used_percent: z.number().nullable(),
  cpu_used_percent: z.number().nullable(),
  disk_total_bytes: z.number().nullable(),
  disk_used_bytes: z.number().nullable(),
  disk_used_percent: z.number().nullable(),
});
export type SystemStatus = z.infer<typeof systemStatusSchema>;

export const systemStatusResponseSchema = z.object({
  firewall_id: z.uuid(),
  status: systemStatusSchema,
  registry_verified: z.boolean(),
});
export const interfaceSchema = z.object({
  identifier: z.string().nullable(),
  description: z.string().nullable(),
  device: z.string().nullable(),
  status: z.string().nullable(),
  enabled: z.boolean().nullable(),
  link_type: z.string().nullable(),
  ipv4: z.array(z.string()),
  ipv6: z.array(z.string()),
  gateways: z.array(z.string()),
  vlan_tag: z.number().nullable(),
});
export type InterfaceInfo = z.infer<typeof interfaceSchema>;

export const interfacesResponseSchema = z.object({
  firewall_id: z.uuid(),
  interfaces: z.array(interfaceSchema),
  registry_verified: z.boolean(),
});

export const ruleSchema = z.object({
  uuid: z.string().nullable(),
  enabled: z.boolean().nullable(),
  action: z.string().nullable(),
  interface: z.string().nullable(),
  direction: z.string().nullable(),
  ip_protocol: z.string().nullable(),
  protocol: z.string().nullable(),
  source: z.string().nullable(),
  source_port: z.string().nullable(),
  destination: z.string().nullable(),
  destination_port: z.string().nullable(),
  description: z.string().nullable(),
  log: z.boolean().nullable(),
  sequence: z.number().nullable(),
});
export type RuleInfo = z.infer<typeof ruleSchema>;

export const rulesResponseSchema = z.object({
  firewall_id: z.uuid(),
  rules: z.array(ruleSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export const natRuleSchema = z.object({
  uuid: z.string().nullable(),
  enabled: z.boolean().nullable(),
  excluded: z.boolean().nullable(),
  interface: z.string().nullable(),
  ip_protocol: z.string().nullable(),
  protocol: z.string().nullable(),
  source: z.string().nullable(),
  source_port: z.string().nullable(),
  destination: z.string().nullable(),
  destination_port: z.string().nullable(),
  target: z.string().nullable(),
  target_port: z.string().nullable(),
  description: z.string().nullable(),
  log: z.boolean().nullable(),
  sequence: z.number().nullable(),
  automatic: z.boolean(),
});
export type NatRule = z.infer<typeof natRuleSchema>;

export const natResponseSchema = z.object({
  firewall_id: z.uuid(),
  rules: z.array(natRuleSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export const logEntrySchema = z.object({
  time: z.string().nullable(),
  action: z.string().nullable(),
  interface: z.string().nullable(),
  direction: z.string().nullable(),
  ip_version: z.number().nullable(),
  protocol: z.string().nullable(),
  source: z.string().nullable(),
  source_country: z.string().nullable(),
  source_port: z.number().nullable(),
  destination: z.string().nullable(),
  destination_port: z.number().nullable(),
  rule: z.string().nullable(),
  reason: z.string().nullable(),
});
export type LogEntry = z.infer<typeof logEntrySchema>;

export const topItemSchema = z.object({ label: z.string(), count: z.number(), country: z.string().nullable() });
export const logSummarySchema = z.object({
  records: z.number(),
  blocked: z.number(),
  passed: z.number(),
  newest: z.string().nullable(),
  oldest: z.string().nullable(),
  top_blocked_sources: z.array(topItemSchema),
  top_blocked_destinations: z.array(topItemSchema),
  top_blocked_ports: z.array(topItemSchema),
  blocked_by_interface: z.array(topItemSchema),
  blocked_by_rule: z.array(topItemSchema),
  blocked_by_country: z.array(topItemSchema),
});
export type LogSummary = z.infer<typeof logSummarySchema>;

export const logsResponseSchema = z.object({
  firewall_id: z.uuid(),
  entries: z.array(logEntrySchema),
  summary: logSummarySchema,
  geoip_enabled: z.boolean(),
  cursor: z.string().nullable(),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export const logsNewResponseSchema = z.object({
  firewall_id: z.uuid(),
  entries: z.array(logEntrySchema),
  cursor: z.string(),
  truncated: z.boolean(),
});

export const trafficInterfaceSchema = z.object({
  interface: z.string(),
  name: z.string().nullable(),
  in_bytes: z.number(),
  out_bytes: z.number(),
  in_packets: z.number(),
  out_packets: z.number(),
});
export type TrafficInterface = z.infer<typeof trafficInterfaceSchema>;

export const trafficResponseSchema = z.object({
  firewall_id: z.uuid(),
  time: z.number().nullable(),
  interfaces: z.array(trafficInterfaceSchema),
  registry_verified: z.boolean(),
});
export type TrafficResponse = z.infer<typeof trafficResponseSchema>;

export const aliasSchema = z.object({
  uuid: z.string().nullable(),
  name: z.string().nullable(),
  type: z.string().nullable(),
  enabled: z.boolean().nullable(),
  description: z.string().nullable(),
  content: z.array(z.string()),
  content_truncated: z.boolean(),
});
export type AliasInfo = z.infer<typeof aliasSchema>;

export const aliasesResponseSchema = z.object({
  firewall_id: z.uuid(),
  aliases: z.array(aliasSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export type SystemStatusResponse = z.infer<typeof systemStatusResponseSchema>;

// Request payloads (write-only secrets live only in these).
export interface FirewallCreateInput {
  name: string;
  base_url: string;
  api_key: string;
  api_secret: string;
  verify_tls: boolean;
  ca_bundle_pem?: string;
}
// Omitted fields are unchanged; ca_bundle_pem "" removes the bundle.
export type FirewallUpdateInput = Partial<FirewallCreateInput> & { allow_writes?: boolean };

export const firewallCreateFormSchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(100, "Max 100 characters"),
  base_url: z
    .string()
    .trim()
    .min(1, "Base URL is required")
    .max(500)
    .refine((v) => /^https:\/\/[^/\s]+\/?$/i.test(v), "Use https://host[:port] with no path"),
  api_key: z.string().min(1, "API key is required").max(512),
  api_secret: z.string().min(1, "API secret is required").max(512),
});

export const loginFormSchema = z.object({
  username: z.string().trim().min(1, "Username is required").max(64),
  password: z.string().min(1, "Password is required").max(128),
});

export const CHANGE_STATUSES = [
  "draft",
  "validated",
  "in_review",
  "approved",
  "applying",
  "applied",
  "rejected",
  "cancelled",
  "failed",
  "stale",
] as const;
export type ChangeStatus = (typeof CHANGE_STATUSES)[number];

export const changeEventSchema = z.object({
  timestamp: z.string(),
  actor_username: z.string(),
  from_status: z.string().nullable(),
  to_status: z.string(),
  note: z.string().nullable(),
});

export const changeSchema = z.object({
  id: z.uuid(),
  firewall_id: z.uuid(),
  kind: z.string(),
  action: z.string(),
  target_uuid: z.string().nullable(),
  proposed: z.record(z.string(), z.unknown()).nullable(),
  base_snapshot: z.record(z.string(), z.unknown()).nullable(),
  status: z.string(),
  high_risk: z.boolean(),
  self_approved: z.boolean(),
  requester_username: z.string(),
  reviewer_username: z.string().nullable(),
  applier_username: z.string().nullable(),
  failure_message: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type ChangeRequest = z.infer<typeof changeSchema>;
export const changeListSchema = z.array(changeSchema);
export const changeDetailSchema = changeSchema.extend({ events: z.array(changeEventSchema) });
export type ChangeDetail = z.infer<typeof changeDetailSchema>;

export interface RuleProposalInput {
  action: "pass" | "block" | "reject";
  interface: string;
  direction: "in" | "out";
  ip_protocol: "inet" | "inet6";
  protocol: "any" | "TCP" | "UDP" | "TCP/UDP" | "ICMP";
  source: string;
  source_port: string;
  destination: string;
  destination_port: string;
  log: boolean;
  enabled: boolean;
  description: string;
}

export interface ForwardProposalInput {
  enabled: boolean;
  interface: string;
  ip_protocol: "inet" | "inet6";
  protocol: "TCP" | "UDP" | "TCP/UDP";
  source: string;
  source_port: string;
  destination: string;
  destination_port: string;
  target: string;
  target_port: string;
  log: boolean;
  description: string;
}

export const ALIAS_TYPES = ["host", "network", "port"] as const;
export interface AliasProposalInput {
  name: string;
  type: (typeof ALIAS_TYPES)[number];
  content: string[];
  description: string;
  enabled?: boolean;
}
