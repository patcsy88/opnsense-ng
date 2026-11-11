import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { RuleProposalInput } from "@/lib/schemas";

interface Props {
  /** When set the form edits this rule: interface and description are fixed. */
  initial?: RuleProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (rule: RuleProposalInput) => void;
  onCancel: () => void;
}

const PORT_PROTOCOLS = ["TCP", "UDP", "TCP/UDP"];
const SELECT = "h-9 w-full rounded-md border border-border bg-card px-2 text-sm";

const ACTIONS = ["pass", "block", "reject"];
const DIRECTIONS = ["in", "out"];
const IP_VERSIONS = ["inet", "inet6"];
const PROTOCOLS = ["any", "TCP", "UDP", "TCP/UDP", "ICMP"];

/** The editable form of a live rule, or null when it uses values this form cannot represent. */
export function toProposal(r: {
  enabled: boolean | null;
  action: string | null;
  interface: string | null;
  direction: string | null;
  ip_protocol: string | null;
  protocol: string | null;
  source: string | null;
  source_port: string | null;
  destination: string | null;
  destination_port: string | null;
  description: string | null;
  log: boolean | null;
  sequence: number | null;
}): RuleProposalInput | null {
  if (r.sequence === null || !r.description || !r.interface) return null;
  const protocol = r.protocol && r.protocol.toLowerCase() !== "any" ? r.protocol.toUpperCase() : "any";
  if (!r.action || !ACTIONS.includes(r.action)) return null;
  if (!r.direction || !DIRECTIONS.includes(r.direction)) return null;
  if (!r.ip_protocol || !IP_VERSIONS.includes(r.ip_protocol)) return null;
  if (!PROTOCOLS.includes(protocol)) return null;
  return {
    action: r.action as RuleProposalInput["action"],
    interface: r.interface,
    direction: r.direction as RuleProposalInput["direction"],
    ip_protocol: r.ip_protocol as RuleProposalInput["ip_protocol"],
    protocol: protocol as RuleProposalInput["protocol"],
    source: r.source ?? "any",
    source_port: r.source_port ?? "",
    destination: r.destination ?? "any",
    destination_port: r.destination_port ?? "",
    log: r.log === true,
    enabled: r.enabled !== false,
    description: r.description,
  };
}

export function RuleForm({ initial, pending, error, onSubmit, onCancel }: Props) {
  const editing = initial !== undefined;
  const [protocol, setProtocol] = useState<RuleProposalInput["protocol"]>(initial?.protocol ?? "any");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const hasPorts = PORT_PROTOCOLS.includes(protocol);

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const fd = new FormData(e.currentTarget);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    const description = text("description");
    const interfaceId = text("interface");
    if (!description) return setFieldError("A description is required; it identifies the rule");
    if (!interfaceId) return setFieldError("Interface is required");
    onSubmit({
      action: text("action") as RuleProposalInput["action"],
      interface: interfaceId,
      direction: text("direction") as RuleProposalInput["direction"],
      ip_protocol: text("ip_protocol") as RuleProposalInput["ip_protocol"],
      protocol,
      source: text("source") || "any",
      source_port: hasPorts ? text("source_port") : "",
      destination: text("destination") || "any",
      destination_port: hasPorts ? text("destination_port") : "",
      log: fd.get("log") === "on",
      enabled: fd.get("enabled") === "on",
      description,
    });
  };

  return (
    <form onSubmit={handle} className="space-y-3" noValidate>
      <div className="space-y-1">
        <Label htmlFor="rule-description">Description</Label>
        <Input
          id="rule-description"
          name="description"
          maxLength={255}
          autoComplete="off"
          defaultValue={initial?.description}
          readOnly={editing}
        />
        <p className="text-xs text-muted-foreground">
          {editing
            ? "The description and interface identify the rule and cannot be changed."
            : "Must be unique. It is also the name you type to apply a high-risk rule."}
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="rule-action">Action</Label>
          <select id="rule-action" name="action" className={SELECT} defaultValue={initial?.action ?? "block"}>
            <option value="pass">Pass</option>
            <option value="block">Block</option>
            <option value="reject">Reject</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="rule-interface">Interface</Label>
          <Input
            id="rule-interface"
            name="interface"
            maxLength={32}
            autoComplete="off"
            placeholder="lan"
            defaultValue={initial?.interface}
            readOnly={editing}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="rule-direction">Direction</Label>
          <select id="rule-direction" name="direction" className={SELECT} defaultValue={initial?.direction ?? "in"}>
            <option value="in">In</option>
            <option value="out">Out</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="rule-ipproto">IP version</Label>
          <select id="rule-ipproto" name="ip_protocol" className={SELECT} defaultValue={initial?.ip_protocol ?? "inet"}>
            <option value="inet">IPv4</option>
            <option value="inet6">IPv6</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="rule-protocol">Protocol</Label>
          <select
            id="rule-protocol"
            className={SELECT}
            value={protocol}
            onChange={(e) => setProtocol(e.target.value as RuleProposalInput["protocol"])}
          >
            <option value="any">any</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="TCP/UDP">TCP/UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="rule-source">Source</Label>
          <Input id="rule-source" name="source" defaultValue={initial?.source ?? "any"} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="rule-destination">Destination</Label>
          <Input id="rule-destination" name="destination" defaultValue={initial?.destination ?? "any"} autoComplete="off" />
        </div>
        {hasPorts && (
          <>
            <div className="space-y-1">
              <Label htmlFor="rule-sport">Source port</Label>
              <Input id="rule-sport" name="source_port" defaultValue={initial?.source_port} autoComplete="off" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="rule-dport">Destination port</Label>
              <Input id="rule-dport" name="destination_port" defaultValue={initial?.destination_port} autoComplete="off" />
            </div>
          </>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        Source and destination: <code>any</code>, an IP address, a CIDR network such as 10.0.0.0/24, or the name of an
        existing alias. Ports: a number, a range such as 8000:8100, or a port alias.
      </p>
      <div className="flex gap-4 text-sm">
        <label className="flex items-center gap-2">
          <input type="checkbox" name="enabled" defaultChecked={initial?.enabled ?? true} /> Enabled
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" name="log" defaultChecked={initial?.log ?? false} /> Log matching packets
        </label>
      </div>
      <p className="text-xs text-muted-foreground">
        Pass-any rules and rules on WAN are marked high risk. {editing ? "The rule keeps its position." : "The rule is placed after the last existing rule."}
      </p>
      {(fieldError || error) && (
        <p role="alert" className="text-sm text-destructive">
          {fieldError ?? error}
        </p>
      )}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : editing ? "Create change request" : "Create request"}
        </Button>
      </DialogFooter>
    </form>
  );
}
