import { Checkbox } from "@/components/ui/checkbox";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type {
  WireguardPeer,
  WireguardPeerProposalInput,
  WireguardTunnel,
} from "@/lib/schemas";

interface Props {
  initial?: WireguardPeerProposalInput;
  tunnels: WireguardTunnel[];
  pending: boolean;
  error: string | null;
  onSubmit: (peer: WireguardPeerProposalInput) => void;
  onCancel: () => void;
}

/** The editable form of a live peer, or null when it cannot be represented. */
export function toWireguardPeerProposal(
  p: WireguardPeer,
): WireguardPeerProposalInput | null {
  if (!p.name || !p.pubkey || p.tunneladdress.length === 0) return null;
  if (p.servers.length === 0) return null;
  const port = p.serverport ? Number(p.serverport) : null;
  const keepalive = p.keepalive ? Number(p.keepalive) : null;
  if (port !== null && !Number.isInteger(port)) return null;
  if (keepalive !== null && !Number.isInteger(keepalive)) return null;
  return {
    name: p.name,
    pubkey: p.pubkey,
    tunneladdress: p.tunneladdress,
    servers: p.servers,
    serveraddress: p.serveraddress,
    serverport: port,
    keepalive,
    enabled: p.enabled,
  };
}

const FIELDS: [string, (f: WireguardPeerProposalInput) => string][] = [
  ["Name", (f) => f.name],
  ["Public key", (f) => f.pubkey],
  ["Tunnel address", (f) => f.tunneladdress.join(", ")],
  ["Tunnels", (f) => [...f.servers].sort().join(", ")],
  ["Endpoint", (f) => f.serveraddress ?? ""],
  ["Endpoint port", (f) => (f.serverport === null ? "" : String(f.serverport))],
  ["Keepalive", (f) => (f.keepalive === null ? "" : String(f.keepalive))],
];

export function wireguardPeerDiff(
  before: WireguardPeerProposalInput,
  after: WireguardPeerProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

const KEY = /^[A-Za-z0-9+/]{43}=$/;

export function WireguardPeerForm({
  initial,
  tunnels,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<WireguardPeerProposalInput | null>(null);

  const read = (form: HTMLFormElement): WireguardPeerProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    const num = (k: string) => (text(k) === "" ? null : Number(text(k)));
    return {
      name: text("name"),
      pubkey: text("pubkey"),
      tunneladdress: text("tunneladdress")
        .split(/[\s,]+/)
        .filter((a) => a !== ""),
      servers: fd.getAll("servers").map(String),
      serveraddress: text("serveraddress") || null,
      serverport: num("serverport"),
      keepalive: num("keepalive"),
      enabled: initial?.enabled ?? true,
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const v = read(e.currentTarget);
    if (!v.name) return setFieldError("A name is required");
    if (!KEY.test(v.pubkey))
      return setFieldError(
        "Paste the peer's public key: 44 characters ending in =. Never paste a private key.",
      );
    if (v.tunneladdress.length === 0)
      return setFieldError(
        "A tunnel address is required, such as 10.10.0.5/32",
      );
    if (v.servers.length === 0)
      return setFieldError("Choose at least one tunnel");
    for (const [label, n, max, min] of [
      ["Endpoint port", v.serverport, 65535, 1],
      ["Keepalive", v.keepalive, 65535, 0],
    ] as const) {
      if (n !== null && (!Number.isInteger(n) || n < min || n > max))
        return setFieldError(`${label} must be a number from ${min} to ${max}`);
    }
    onSubmit(v);
  };

  const live = draft ?? initial;
  const changes = editing && live ? wireguardPeerDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="wp-name">Name</Label>
          <Input
            id="wp-name"
            name="name"
            maxLength={64}
            autoComplete="off"
            defaultValue={initial?.name}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wp-address">Tunnel address</Label>
          <Input
            id="wp-address"
            name="tunneladdress"
            autoComplete="off"
            placeholder="10.10.0.5/32"
            defaultValue={initial?.tunneladdress.join(", ")}
          />
        </div>
        <div className="col-span-2 space-y-1">
          <Label htmlFor="wp-pubkey">Public key</Label>
          <Input
            id="wp-pubkey"
            name="pubkey"
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-xs"
            defaultValue={initial?.pubkey}
          />
        </div>
        <fieldset className="col-span-2 space-y-1">
          <legend className="text-sm font-medium">Tunnels</legend>
          {tunnels.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The firewall has no tunnels.
            </p>
          ) : (
            tunnels
              .filter((t) => t.uuid)
              .map((t) => (
                <Checkbox
                  key={t.uuid}
                  name="servers"
                  value={t.uuid as string}
                  defaultChecked={initial?.servers.includes(t.uuid as string)}
                >
                  {t.name ?? t.uuid}{" "}
                  <span className="font-mono text-xs text-muted-foreground">
                    {t.tunneladdress.join(", ")}
                  </span>
                </Checkbox>
              ))
          )}
        </fieldset>
        <div className="space-y-1">
          <Label htmlFor="wp-endpoint">Endpoint (optional)</Label>
          <Input
            id="wp-endpoint"
            name="serveraddress"
            autoComplete="off"
            defaultValue={initial?.serveraddress ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wp-port">Endpoint port (optional)</Label>
          <Input
            id="wp-port"
            name="serverport"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.serverport ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="wp-keepalive">Keepalive (optional)</Label>
          <Input
            id="wp-keepalive"
            name="keepalive"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.keepalive ?? ""}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Only the peer&apos;s public key is used. Generate the key pair in the
        peer&apos;s own WireGuard app and never paste a private key here. A
        preshared key cannot be set here and is left as it is. Changing a
        peer&apos;s key, address or tunnels, or disabling or deleting it, is
        high risk and needs an admin to approve it. Applying reconfigures
        WireGuard, so active VPN sessions may drop for a moment.
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
      <DialogFooter variant="bare" className="px-0 pb-0">
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
