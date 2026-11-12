import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { ForwardProposalInput, NatRule } from "@/lib/schemas";

interface Props {
  /** When set the form edits this forward: interface and description are fixed. */
  initial?: ForwardProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (forward: ForwardProposalInput) => void;
  onCancel: () => void;
}

const SELECT = "h-9 w-full rounded-md border border-border bg-card px-2 text-sm";
const PROTOCOLS = ["TCP", "UDP", "TCP/UDP"];
const IP_VERSIONS = ["inet", "inet6"];

/** The editable form of a live port forward, or null when it uses values this form cannot represent. */
export function toForwardProposal(r: NatRule): ForwardProposalInput | null {
  if (r.automatic || r.excluded || r.sequence === null || !r.description || !r.interface) return null;
  const protocol = r.protocol?.toUpperCase() ?? "";
  if (!PROTOCOLS.includes(protocol)) return null;
  if (!r.ip_protocol || !IP_VERSIONS.includes(r.ip_protocol)) return null;
  if (!r.destination || !r.target) return null;
  return {
    enabled: r.enabled !== false,
    interface: r.interface,
    ip_protocol: r.ip_protocol as ForwardProposalInput["ip_protocol"],
    protocol: protocol as ForwardProposalInput["protocol"],
    source: r.source ?? "any",
    source_port: r.source_port ?? "",
    destination: r.destination,
    destination_port: r.destination_port ?? "",
    target: r.target,
    target_port: r.target_port ?? "",
    log: r.log === true,
    description: r.description,
  };
}

export function ForwardForm({ initial, pending, error, onSubmit, onCancel }: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const fd = new FormData(e.currentTarget);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    const description = text("description");
    const interfaceId = text("interface");
    if (!description) return setFieldError("A description is required; it identifies the forward");
    if (!interfaceId) return setFieldError("Interface is required");
    if (!text("destination")) return setFieldError("Destination is required, for example wanip");
    if (!text("target")) return setFieldError("The redirect target is required");
    onSubmit({
      enabled: fd.get("enabled") === "on",
      interface: interfaceId,
      ip_protocol: text("ip_protocol") as ForwardProposalInput["ip_protocol"],
      protocol: text("protocol") as ForwardProposalInput["protocol"],
      source: text("source") || "any",
      source_port: text("source_port"),
      destination: text("destination"),
      destination_port: text("destination_port"),
      target: text("target"),
      target_port: text("target_port"),
      log: fd.get("log") === "on",
      description,
    });
  };

  return (
    <form onSubmit={handle} className="space-y-3" noValidate>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="fwd-description">Description</Label>
          <Input
            id="fwd-description"
            name="description"
            maxLength={255}
            autoComplete="off"
            defaultValue={initial?.description}
            readOnly={editing}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-interface">Interface</Label>
          <Input
            id="fwd-interface"
            name="interface"
            maxLength={32}
            autoComplete="off"
            placeholder="wan"
            defaultValue={initial?.interface}
            readOnly={editing}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {editing
          ? "The description and interface identify the forward and cannot be changed."
          : "The description must be unique. It is also the text you type to apply a high-risk forward."}
      </p>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="fwd-ipproto">IP version</Label>
          <select id="fwd-ipproto" name="ip_protocol" className={SELECT} defaultValue={initial?.ip_protocol ?? "inet"}>
            <option value="inet">IPv4</option>
            <option value="inet6">IPv6</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-protocol">Protocol</Label>
          <select id="fwd-protocol" name="protocol" className={SELECT} defaultValue={initial?.protocol ?? "TCP"}>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="TCP/UDP">TCP/UDP</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-source">Source</Label>
          <Input id="fwd-source" name="source" defaultValue={initial?.source ?? "any"} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-sport">Source port</Label>
          <Input id="fwd-sport" name="source_port" defaultValue={initial?.source_port} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-destination">Destination</Label>
          <Input
            id="fwd-destination"
            name="destination"
            placeholder="wanip"
            defaultValue={initial?.destination}
            autoComplete="off"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-dport">Destination port</Label>
          <Input id="fwd-dport" name="destination_port" defaultValue={initial?.destination_port} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-target">Redirect target IP</Label>
          <Input id="fwd-target" name="target" defaultValue={initial?.target} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="fwd-tport">Redirect target port</Label>
          <Input id="fwd-tport" name="target_port" defaultValue={initial?.target_port} autoComplete="off" />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Source and destination: <code>any</code>, an IP address, a CIDR network, an alias name, or for the
        destination the interface address such as <code>wanip</code>. The redirect target is one IP address or an
        alias. Ports: a number, a range such as 8000:8100 (not for the redirect port), or a port alias.
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
        Forwards on WAN, and forwards that accept any source on an empty or ranged port, are high risk. A forward
        does not open the traffic by itself: create the matching pass rule through a separate rule request.{" "}
        {editing ? "The forward keeps its position." : "The forward is placed after the last existing forward."}
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
          {pending ? "Saving…" : "Create change request"}
        </Button>
      </DialogFooter>
    </form>
  );
}
