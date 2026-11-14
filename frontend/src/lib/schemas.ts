// Zod schemas mirroring backend/app/auth/schemas.py and backend/app/api/schemas.py.
import { z } from "zod";

export const ROLES = ["admin", "network_admin", "security_admin", "read_only"] as const;
export const roleSchema = z.enum(ROLES);
export type Role = z.infer<typeof roleSchema>;

export const userSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  role: roleSchema,
  mfa_enabled: z.boolean().default(false),
  mfa_enrolment_required: z.boolean().default(false),
  must_change_password: z.boolean().default(false),
});
export type User = z.infer<typeof userSchema>;

export const loginResponseSchema = z.object({
  user: userSchema.nullish(),
  csrf_token: z.string().nullish(),
  mfa_required: z.boolean().default(false),
  challenge: z.string().nullish(),
});

export const userRowSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  role: roleSchema,
  is_active: z.boolean(),
  mfa_enabled: z.boolean(),
  must_change_password: z.boolean(),
  created_at: z.string(),
  sessions: z.number().int(),
});
export type UserRow = z.infer<typeof userRowSchema>;
export const userListSchema = z.array(userRowSchema);
export const tempPasswordSchema = z.object({ user: userRowSchema, temporary_password: z.string() });

export const mfaStatusSchema = z.object({
  enabled: z.boolean(),
  required: z.boolean(),
  recovery_codes_left: z.number().int(),
});
export const mfaEnrolStartSchema = z.object({
  secret: z.string(),
  otpauth_uri: z.string(),
  qr: z.array(z.array(z.boolean())),
});
export const recoveryCodesSchema = z.object({ recovery_codes: z.array(z.string()) });
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

export const overviewEntrySchema = z.object({
  id: z.uuid(),
  name: z.string(),
  reachable: z.boolean(),
  status: z.string(),
  message: z.string(),
  hostname: z.string().nullable(),
  version: z.string().nullable(),
  uptime: z.string().nullable(),
  cpu_used_percent: z.number().nullable(),
  memory_used_percent: z.number().nullable(),
  disk_used_percent: z.number().nullable(),
  checked_at: z.number(),
});
export const overviewSchema = z.object({
  firewalls: z.array(overviewEntrySchema),
  truncated: z.boolean(),
});
export type OverviewEntry = z.infer<typeof overviewEntrySchema>;

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

export const auditEntrySchema = z.object({
  id: z.uuid(),
  timestamp: z.string(),
  username: z.string().nullable(),
  action: z.string(),
  firewall_id: z.uuid().nullable(),
  outcome: z.string(),
  source_ip: z.string().nullable(),
  user_agent: z.string().nullable(),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export const auditPageSchema = z.object({
  items: z.array(auditEntrySchema),
  total: z.number(),
  page: z.number(),
  page_size: z.number(),
  retention_days: z.number(),
  purgeable: z.number(),
});

export const auditPurgeSchema = z.object({ removed: z.number(), cutoff: z.string() });

export const topDomainSchema = z.object({
  domain: z.string(),
  count: z.number(),
  blocklist: z.string().nullable(),
});
export type TopDomain = z.infer<typeof topDomainSchema>;

export const dnsResponseSchema = z.object({
  firewall_id: z.uuid(),
  stats_available: z.boolean(),
  totals_available: z.boolean(),
  queries: z.number().nullable(),
  cache_hits: z.number().nullable(),
  cache_misses: z.number().nullable(),
  hit_rate: z.number().nullable(),
  uptime_seconds: z.number().nullable(),
  logged_queries: z.number().nullable(),
  blocked: z.number().nullable(),
  blocked_percent: z.number().nullable(),
  blocklist_size: z.number().nullable(),
  top_queried: z.array(topDomainSchema),
  top_blocked: z.array(topDomainSchema),
  registry_verified: z.boolean(),
});

export const wireguardRecordSchema = z.object({
  interface: z.string(),
  type: z.string(),
  tunnel_name: z.string().nullable(),
  name: z.string().nullable(),
  status: z.string().nullable(),
  endpoint: z.string().nullable(),
  listen_port: z.number().nullable(),
  allowed_ips: z.array(z.string()),
  latest_handshake: z.string().nullable(),
  rx_bytes: z.number().nullable(),
  tx_bytes: z.number().nullable(),
  keepalive: z.number().nullable(),
});
export type WireguardRecord = z.infer<typeof wireguardRecordSchema>;

export const wireguardResponseSchema = z.object({
  firewall_id: z.uuid(),
  records: z.array(wireguardRecordSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export const leaseSchema = z.object({
  address: z.string(),
  ip_version: z.number(),
  hostname: z.string().nullable(),
  interface: z.string().nullable(),
  lease_type: z.string().nullable(),
  vendor: z.string().nullable(),
  expires: z.string().nullable(),
});
export type LeaseInfo = z.infer<typeof leaseSchema>;

export const leasesResponseSchema = z.object({
  firewall_id: z.uuid(),
  leases: z.array(leaseSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
});

export const serviceSchema = z.object({
  id: z.string(),
  name: z.string(),
  instance: z.string().nullable().optional(),
  description: z.string().nullable(),
  running: z.boolean(),
  locked: z.boolean(),
});
export type ServiceInfo = z.infer<typeof serviceSchema>;

export const serviceActionSchema = z.object({
  firewall_id: z.uuid(),
  service: z.string(),
  instance: z.string().nullable(),
  action: z.string(),
  was_running: z.boolean(),
  running: z.boolean(),
  confirmed: z.boolean(),
  message: z.string(),
});
export type ServiceAction = z.infer<typeof serviceActionSchema>;

export const servicesResponseSchema = z.object({
  firewall_id: z.uuid(),
  services: z.array(serviceSchema),
  truncated: z.boolean(),
  registry_verified: z.boolean(),
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

export const mfaCodeFormSchema = z.object({
  code: z.string().trim().min(1, "Enter a code").max(32),
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
