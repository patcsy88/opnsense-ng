import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type {
  WireguardPeer,
  WireguardTunnel,
  WireguardTunnelProposalInput,
} from "@/lib/schemas";

interface Props {
  initial?: WireguardTunnelProposalInput;
  peers: WireguardPeer[];
  pending: boolean;
  error: string | null;
  onSubmit: (tunnel: WireguardTunnelProposalInput) => void;
  onCancel: () => void;
}

/** The editable form of a live tunnel, or null when it cannot be represented. */
export function toWireguardTunnelProposal(
  t: WireguardTunnel,
): WireguardTunnelProposalInput | null {
  if (!t.name || !t.port || t.tunneladdress.length === 0) return null;
  const port = Number(t.port);
  const mtu = t.mtu ? Number(t.mtu) : null;
  if (!Number.isInteger(port)) return null;
  if (mtu !== null && !Number.isInteger(mtu)) return null;
  return {
    name: t.name,
    port,
    tunneladdress: t.tunneladdress,
    mtu,
    disableroutes: t.disableroutes,
    peers: t.peers,
    enabled: t.enabled,
  };
}

const FIELDS: [string, (f: WireguardTunnelProposalInput) => string][] = [
  ["Name", (f) => f.name],
  ["Port", (f) => String(f.port)],
  ["Tunnel address", (f) => f.tunneladdress.join(", ")],
  ["MTU", (f) => (f.mtu === null ? "" : String(f.mtu))],
  ["Disable routes", (f) => (f.disableroutes ? "yes" : "no")],
  ["Peers", (f) => [...f.peers].sort().join(", ")],
];

export function wireguardTunnelDiff(
  before: WireguardTunnelProposalInput,
  after: WireguardTunnelProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

export function WireguardTunnelForm({
  initial,
  peers,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<WireguardTunnelProposalInput | null>(null);

  const read = (form: HTMLFormElement): WireguardTunnelProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      name: text("name"),
      port: text("port") === "" ? Number.NaN : Number(text("port")),
      tunneladdress: text("tunneladdress")
        .split(/[\s,]+/)
        .filter((a) => a !== ""),
      mtu: text("mtu") === "" ? null : Number(text("mtu")),
      disableroutes: fd.get("disableroutes") !== null,
      peers: fd.getAll("peers").map(String),
      enabled: initial?.enabled ?? true,
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const v = read(e.currentTarget);
    if (!v.name) return setFieldError("A name is required");
    if (!Number.isInteger(v.port) || v.port < 1 || v.port > 65535)
      return setFieldError("The listen port must be a number from 1 to 65535");
    if (v.tunneladdress.length === 0)
      return setFieldError(
        "A tunnel address is required, such as 10.10.0.1/24",
      );
    if (v.tunneladdress.some((a) => !a.includes("/")))
      return setFieldError("Give the tunnel address a prefix, such as /24");
    if (
      v.mtu !== null &&
      (!Number.isInteger(v.mtu) || v.mtu < 576 || v.mtu > 9000)
    )
      return setFieldError("MTU must be a number from 576 to 9000");
    onSubmit(v);
  };

  const live = draft ?? initial;
  const changes = editing && live ? wireguardTunnelDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="wt-name">Name</Label>
          <Input
            id="wt-name"
            name="name"
            maxLength={64}
            autoComplete="off"
            defaultValue={initial?.name}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wt-port">Listen port</Label>
          <Input
            id="wt-port"
            name="port"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.port}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wt-address">Tunnel address</Label>
          <Input
            id="wt-address"
            name="tunneladdress"
            autoComplete="off"
            placeholder="10.10.0.1/24"
            defaultValue={initial?.tunneladdress.join(", ")}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wt-mtu">MTU (optional)</Label>
          <Input
            id="wt-mtu"
            name="mtu"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.mtu ?? ""}
          />
        </div>
        <label className="col-span-2 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            name="disableroutes"
            defaultChecked={initial?.disableroutes}
          />
          Do not add routes for the peers&apos; addresses
        </label>
        <fieldset className="col-span-2 space-y-1">
          <legend className="text-sm font-medium">Peers</legend>
          {peers.filter((p) => p.uuid).length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The firewall has no peers yet.
            </p>
          ) : (
            peers
              .filter((p) => p.uuid)
              .map((p) => (
                <label key={p.uuid} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    name="peers"
                    value={p.uuid as string}
                    defaultChecked={initial?.peers.includes(p.uuid as string)}
                  />
                  {p.name ?? p.uuid}
                </label>
              ))
          )}
        </fieldset>
      </div>
      <p className="text-xs text-muted-foreground">
        {editing
          ? "The tunnel's keys are left as they are."
          : "The firewall generates this tunnel's private key itself; it is never shown or handled here."}{" "}
        Every tunnel change is high risk and needs an admin to approve it.
        Applying reconfigures WireGuard, so active VPN sessions may drop.
      </p>
      {editing && (
        <div
          aria-label="Changes"
          className="rounded-md border border-border p-2 text-sm"
        >
          {changes.length === 0 ? (
            <p className="text-muted-foreground">No changes yet.</p>
          ) : (
            <ul className="space-y-1">
              {changes.map(([label, before, after]) => (
                <li key={label}>
                  <span className="text-muted-foreground">{label}:</span>{" "}
                  <span className="break-all font-mono text-xs line-through">
                    {before}
                  </span>{" "}
                  → <span className="break-all font-mono text-xs">{after}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {(fieldError || error) && (
        <p role="alert" className="text-sm text-destructive">
          {fieldError ?? error}
        </p>
      )}
      <DialogFooter>
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={pending}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : "Create change request"}
        </Button>
      </DialogFooter>
    </form>
  );
}
