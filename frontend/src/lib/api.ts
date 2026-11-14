// The single typed API client. Only relative /api/ URLs are ever requested.
import type { z } from "zod";
import {
  connectivitySchema,
  firewallListSchema,
  firewallOptionListSchema,
  serviceActionSchema,
  dnsmasqDomainsResponseSchema,
  dnsmasqHostsResponseSchema,
  overviewSchema,
  firewallSchema,
  loginResponseSchema,
  tempPasswordSchema,
  userListSchema,
  userRowSchema,
  mfaEnrolStartSchema,
  mfaStatusSchema,
  recoveryCodesSchema,
  logoutAllResponseSchema,
  interfacesResponseSchema,
  aliasesResponseSchema,
  changeDetailSchema,
  changeListSchema,
  rulesResponseSchema,
  logsResponseSchema,
  auditPageSchema,
  auditPurgeSchema,
  dnsResponseSchema,
  leasesResponseSchema,
  wireguardResponseSchema,
  servicesResponseSchema,
  trafficResponseSchema,
  natResponseSchema,
  logsNewResponseSchema,
  systemStatusResponseSchema,
  userSchema,
  type AliasProposalInput,
  type ForwardProposalInput,
  type DomainProposalInput,
  type HostProposalInput,
  type RuleProposalInput,
  type FirewallCreateInput,
  type FirewallUpdateInput,
} from "./schemas";

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "unsupported_media"
  | "rate_limited"
  | "not_found"
  | "conflict"
  | "validation"
  | "server"
  | "network"
  | "schema";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number;
  readonly retryAfterSeconds?: number;
  constructor(kind: ApiErrorKind, status: number, message: string, retryAfterSeconds?: number) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIES = ["__Host-csrf_token", "csrf_token"]; // prefixed in prod, plain in DEV_MODE
const CSRF_HEADER = "X-CSRF-Token";

export function readCsrfToken(cookieString: string = document.cookie): string | null {
  for (const part of cookieString.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    if (CSRF_COOKIES.includes(name)) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

let unauthorizedHandler: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const n = Number(value);
  if (Number.isFinite(n) && n >= 0) return Math.ceil(n);
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, Math.ceil((date - Date.now()) / 1000));
}

// FastAPI `detail` is a string, a validation-error list, or {status, message}.
function extractMessage(body: unknown, fallback: string): string {
  if (typeof body !== "object" || body === null || !("detail" in body)) return fallback;
  const detail = (body as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (typeof d === "object" && d && "msg" in d ? String((d as { msg: unknown }).msg) : ""))
      .filter(Boolean);
    return msgs.length ? msgs.join("; ") : fallback;
  }
  if (typeof detail === "object" && detail && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  return fallback;
}

function kindForStatus(status: number): ApiErrorKind {
  switch (status) {
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 415:
      return "unsupported_media";
    case 422:
    case 400:
      return "validation";
    case 429:
      return "rate_limited";
    default:
      return "server";
  }
}

interface RequestOptions<T> {
  body?: unknown;
  schema?: z.ZodType<T>;
  /** Do not trigger the global 401 handler (login attempts, session bootstrap). */
  skipUnauthorizedHandler?: boolean;
}

export async function request<T = void>(
  method: string,
  path: string,
  opts: RequestOptions<T> = {},
): Promise<T> {
  if (!path.startsWith("/api/")) {
    throw new Error("API client only accepts relative /api/ paths");
  }
  const headers: Record<string, string> = { Accept: "application/json" };
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  if (MUTATING.has(method)) {
    const csrf = readCsrfToken();
    if (csrf) headers[CSRF_HEADER] = csrf;
  }

  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError("network", 0, "Cannot reach the server");
  }

  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error body */
    }
    const kind = kindForStatus(res.status);
    const err = new ApiError(
      res.status >= 500 && kind === "server" ? "server" : kind,
      res.status,
      extractMessage(body, `Request failed (${res.status})`),
      kind === "rate_limited" ? parseRetryAfter(res.headers.get("Retry-After")) : undefined,
    );
    if (kind === "unauthorized" && !opts.skipUnauthorizedHandler) unauthorizedHandler?.();
    throw err;
  }

  if (res.status === 204 || !opts.schema) return undefined as T;
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    throw new ApiError("schema", res.status, "Unexpected response from server");
  }
  const parsed = opts.schema.safeParse(json);
  if (!parsed.success) throw new ApiError("schema", res.status, "Unexpected response from server");
  return parsed.data;
}

const base = "/api/v1";

export const api = {
  login: (username: string, password: string) =>
    request("POST", `${base}/auth/login`, {
      body: { username, password },
      schema: loginResponseSchema,
      skipUnauthorizedHandler: true,
    }),
  loginMfa: (challenge: string, code: string) =>
    request("POST", `${base}/auth/login/mfa`, {
      body: { challenge, code },
      schema: loginResponseSchema,
      skipUnauthorizedHandler: true,
    }),
  changePassword: (currentPassword: string, newPassword: string, code?: string) =>
    request("POST", `${base}/auth/password`, {
      body: { current_password: currentPassword, new_password: newPassword, ...(code ? { code } : {}) },
      skipUnauthorizedHandler: true,
    }),
  listUsers: () => request("GET", `${base}/users`, { schema: userListSchema }),
  createUser: (username: string, role: string) =>
    request("POST", `${base}/users`, { body: { username, role }, schema: tempPasswordSchema }),
  changeUserRole: (id: string, role: string) =>
    request("POST", `${base}/users/${encodeURIComponent(id)}/role`, { body: { role }, schema: userRowSchema }),
  deactivateUser: (id: string) =>
    request("POST", `${base}/users/${encodeURIComponent(id)}/deactivate`, { body: {}, schema: userRowSchema }),
  reactivateUser: (id: string) =>
    request("POST", `${base}/users/${encodeURIComponent(id)}/reactivate`, { body: {}, schema: userRowSchema }),
  resetUserPassword: (id: string) =>
    request("POST", `${base}/users/${encodeURIComponent(id)}/reset-password`, {
      body: {},
      schema: tempPasswordSchema,
    }),
  resetUserMfa: (id: string, password: string, code?: string) =>
    request("POST", `${base}/users/${encodeURIComponent(id)}/reset-mfa`, {
      body: { password, ...(code ? { code } : {}) },
      schema: userRowSchema,
      skipUnauthorizedHandler: true,
    }),
  mfaStatus: () => request("GET", `${base}/auth/mfa`, { schema: mfaStatusSchema }),
  mfaEnrolStart: (password: string) =>
    request("POST", `${base}/auth/mfa/enrol/start`, {
      body: { password },
      schema: mfaEnrolStartSchema,
      skipUnauthorizedHandler: true,
    }),
  mfaEnrolConfirm: (code: string) =>
    request("POST", `${base}/auth/mfa/enrol/confirm`, {
      body: { code },
      schema: recoveryCodesSchema,
      skipUnauthorizedHandler: true,
    }),
  mfaDisable: (password: string, code: string) =>
    request("POST", `${base}/auth/mfa/disable`, {
      body: { password, code },
      skipUnauthorizedHandler: true,
    }),
  mfaRegenerateCodes: (password: string, code: string) =>
    request("POST", `${base}/auth/mfa/recovery-codes`, {
      body: { password, code },
      schema: recoveryCodesSchema,
      skipUnauthorizedHandler: true,
    }),
  logout: () => request("POST", `${base}/auth/logout`, { skipUnauthorizedHandler: true }),
  logoutAll: () =>
    request("POST", `${base}/auth/logout-all`, {
      schema: logoutAllResponseSchema,
      skipUnauthorizedHandler: true,
    }),
  me: () =>
    request("GET", `${base}/auth/me`, { schema: userSchema, skipUnauthorizedHandler: true }),
  listFirewalls: () => request("GET", `${base}/firewalls`, { schema: firewallListSchema }),
  listFirewallOptions: () =>
    request("GET", `${base}/firewalls/options`, { schema: firewallOptionListSchema }),
  getOverview: () => request("GET", `${base}/firewalls/overview`, { schema: overviewSchema }),
  createFirewall: (input: FirewallCreateInput) =>
    request("POST", `${base}/firewalls`, { body: input, schema: firewallSchema }),
  updateFirewall: (id: string, input: FirewallUpdateInput) =>
    request("PATCH", `${base}/firewalls/${encodeURIComponent(id)}`, {
      body: input,
      schema: firewallSchema,
    }),
  deleteFirewall: (id: string) =>
    request("DELETE", `${base}/firewalls/${encodeURIComponent(id)}`),
  connectivity: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/connectivity`, {
      schema: connectivitySchema,
    }),
  firewallAliases: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/firewall/aliases`, {
      schema: aliasesResponseSchema,
    }),
  firewallRules: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/firewall/rules`, {
      schema: rulesResponseSchema,
    }),
  natRules: (id: string, kind: "port-forwards" | "outbound") =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/firewall/nat/${kind}`, {
      schema: natResponseSchema,
    }),
  firewallLogs: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/firewall/logs`, {
      schema: logsResponseSchema,
    }),
  firewallLogsNew: (id: string, since: string) =>
    request(
      "GET",
      `${base}/firewalls/${encodeURIComponent(id)}/firewall/logs/new?since=${encodeURIComponent(since)}`,
      { schema: logsNewResponseSchema },
    ),
  listAudit: (params: {
    username?: string;
    action?: string;
    firewallId?: string;
    outcome?: string;
    since?: string;
    until?: string;
    page?: number;
  }) => {
    const q = new URLSearchParams();
    if (params.username) q.set("username", params.username);
    if (params.action) q.set("action", params.action);
    if (params.firewallId) q.set("firewall_id", params.firewallId);
    if (params.outcome) q.set("outcome", params.outcome);
    if (params.since) q.set("since", params.since);
    if (params.until) q.set("until", params.until);
    q.set("page", String(params.page ?? 1));
    return request("GET", `${base}/audit?${q.toString()}`, { schema: auditPageSchema });
  },
  purgeAudit: () =>
    request("POST", `${base}/audit/purge`, { body: { confirm: "PURGE" }, schema: auditPurgeSchema }),
  dns: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/dns`, {
      schema: dnsResponseSchema,
    }),
  wireguard: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/vpn/wireguard`, {
      schema: wireguardResponseSchema,
    }),
  dhcpLeases: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/dhcp/leases`, {
      schema: leasesResponseSchema,
    }),
  services: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/services`, {
      schema: servicesResponseSchema,
    }),
  dnsmasqHosts: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/dnsmasq/hosts`, {
      schema: dnsmasqHostsResponseSchema,
    }),
  dnsmasqDomains: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/dnsmasq/domains`, {
      schema: dnsmasqDomainsResponseSchema,
    }),
  stageDomain: (firewallId: string, override: DomainProposalInput) =>
    request("POST", `${base}/changes/dnsmasq-domains`, {
      body: { firewall_id: firewallId, override },
      schema: changeDetailSchema,
    }),
  stageDomainUpdate: (firewallId: string, uuid: string, override: DomainProposalInput) =>
    request("POST", `${base}/changes/dnsmasq-domains/${encodeURIComponent(uuid)}/update`, {
      body: { firewall_id: firewallId, override },
      schema: changeDetailSchema,
    }),
  stageDomainDelete: (firewallId: string, uuid: string) =>
    request("POST", `${base}/changes/dnsmasq-domains/${encodeURIComponent(uuid)}/delete`, {
      body: { firewall_id: firewallId },
      schema: changeDetailSchema,
    }),
  stageHost: (firewallId: string, host: HostProposalInput) =>
    request("POST", `${base}/changes/dnsmasq-hosts`, {
      body: { firewall_id: firewallId, host },
      schema: changeDetailSchema,
    }),
  stageHostUpdate: (firewallId: string, uuid: string, host: HostProposalInput) =>
    request("POST", `${base}/changes/dnsmasq-hosts/${encodeURIComponent(uuid)}/update`, {
      body: { firewall_id: firewallId, host },
      schema: changeDetailSchema,
    }),
  stageHostDelete: (firewallId: string, uuid: string) =>
    request("POST", `${base}/changes/dnsmasq-hosts/${encodeURIComponent(uuid)}/delete`, {
      body: { firewall_id: firewallId },
      schema: changeDetailSchema,
    }),
  controlService: (
    id: string,
    action: "start" | "stop" | "restart",
    body: { service: string; instance?: string | null; confirm_name?: string },
  ) =>
    request("POST", `${base}/firewalls/${encodeURIComponent(id)}/services/${action}`, {
      body,
      schema: serviceActionSchema,
    }),
  traffic: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/traffic`, {
      schema: trafficResponseSchema,
    }),
  interfaces: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/interfaces`, {
      schema: interfacesResponseSchema,
    }),
  listChanges: (params: { status?: string; firewallId?: string } = {}) => {
    const q = new URLSearchParams();
    if (params.status) q.set("status", params.status);
    if (params.firewallId) q.set("firewall_id", params.firewallId);
    const qs = q.toString();
    return request("GET", `${base}/changes${qs ? `?${qs}` : ""}`, { schema: changeListSchema });
  },
  getChange: (id: string) =>
    request("GET", `${base}/changes/${encodeURIComponent(id)}`, { schema: changeDetailSchema }),
  stageAlias: (firewallId: string, alias: AliasProposalInput) =>
    request("POST", `${base}/changes/aliases`, {
      body: { firewall_id: firewallId, alias },
      schema: changeDetailSchema,
    }),
  stageAliasUpdate: (firewallId: string, uuid: string, alias: AliasProposalInput & { enabled?: boolean }) =>
    request("POST", `${base}/changes/aliases/${encodeURIComponent(uuid)}/update`, {
      body: { firewall_id: firewallId, alias },
      schema: changeDetailSchema,
    }),
  stageAliasDelete: (firewallId: string, uuid: string) =>
    request("POST", `${base}/changes/aliases/${encodeURIComponent(uuid)}/delete`, {
      body: { firewall_id: firewallId },
      schema: changeDetailSchema,
    }),
  stageRule: (firewallId: string, rule: RuleProposalInput) =>
    request("POST", `${base}/changes/rules`, {
      body: { firewall_id: firewallId, rule },
      schema: changeDetailSchema,
    }),
  stageRuleUpdate: (firewallId: string, uuid: string, rule: RuleProposalInput) =>
    request("POST", `${base}/changes/rules/${encodeURIComponent(uuid)}/update`, {
      body: { firewall_id: firewallId, rule },
      schema: changeDetailSchema,
    }),
  stageRuleDelete: (firewallId: string, uuid: string) =>
    request("POST", `${base}/changes/rules/${encodeURIComponent(uuid)}/delete`, {
      body: { firewall_id: firewallId },
      schema: changeDetailSchema,
    }),
  stageRuleToggle: (firewallId: string, uuid: string, enabled: boolean) =>
    request("POST", `${base}/changes/rules/${encodeURIComponent(uuid)}/toggle`, {
      body: { firewall_id: firewallId, enabled },
      schema: changeDetailSchema,
    }),
  stageForward: (firewallId: string, forward: ForwardProposalInput) =>
    request("POST", `${base}/changes/forwards`, {
      body: { firewall_id: firewallId, forward },
      schema: changeDetailSchema,
    }),
  stageForwardUpdate: (firewallId: string, uuid: string, forward: ForwardProposalInput) =>
    request("POST", `${base}/changes/forwards/${encodeURIComponent(uuid)}/update`, {
      body: { firewall_id: firewallId, forward },
      schema: changeDetailSchema,
    }),
  stageForwardToggle: (firewallId: string, uuid: string, enabled: boolean) =>
    request("POST", `${base}/changes/forwards/${encodeURIComponent(uuid)}/toggle`, {
      body: { firewall_id: firewallId, enabled },
      schema: changeDetailSchema,
    }),
  stageForwardDelete: (firewallId: string, uuid: string) =>
    request("POST", `${base}/changes/forwards/${encodeURIComponent(uuid)}/delete`, {
      body: { firewall_id: firewallId },
      schema: changeDetailSchema,
    }),
  moveChange: (id: string, verb: "submit" | "approve" | "reject" | "cancel", note?: string) =>
    request("POST", `${base}/changes/${encodeURIComponent(id)}/${verb}`, {
      body: note ? { note } : {},
      schema: changeDetailSchema,
    }),
  applyChange: (id: string, confirmName?: string) =>
    request("POST", `${base}/changes/${encodeURIComponent(id)}/apply`, {
      body: confirmName ? { confirm_name: confirmName } : {},
      schema: changeDetailSchema,
    }),
  systemStatus: (id: string) =>
    request("GET", `${base}/firewalls/${encodeURIComponent(id)}/system/status`, {
      schema: systemStatusResponseSchema,
    }),
};
