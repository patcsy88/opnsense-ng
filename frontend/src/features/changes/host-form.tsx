import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { DnsmasqHost, HostProposalInput } from "@/lib/schemas";

interface Props {
  initial?: HostProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (host: HostProposalInput) => void;
  onCancel: () => void;
}

const split = (value: string): string[] =>
  value
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter((v) => v !== "");

/** The editable form of a live host entry, or null when it cannot be represented. */
export function toHostProposal(h: DnsmasqHost): HostProposalInput | null {
  if (!h.host || !h.description || h.ips.length === 0) return null;
  return {
    host: h.host,
    domain: h.domain ?? "",
    ips: h.ips,
    hwaddrs: h.hwaddrs,
    cnames: h.cnames,
    ignore: h.ignore,
    description: h.description,
  };
}

const FIELDS: [string, (h: HostProposalInput) => string][] = [
  ["Host", (h) => h.host],
  ["Domain", (h) => h.domain],
  ["IP addresses", (h) => h.ips.join(", ")],
  ["MAC addresses", (h) => h.hwaddrs.join(", ")],
  ["Aliases", (h) => h.cnames.join(", ")],
  ["Ignore", (h) => (h.ignore ? "Yes" : "No")],
  ["Description", (h) => h.description],
];

/** Changed fields between the current entry and the proposal, as [label, before, after]. */
export function hostDiff(
  before: HostProposalInput,
  after: HostProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

export function HostForm({
  initial,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<HostProposalInput | null>(null);

  const read = (form: HTMLFormElement): HostProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      host: text("host").toLowerCase(),
      domain: text("domain").toLowerCase(),
      ips: split(text("ips")),
      hwaddrs: split(text("hwaddrs")).map((m) => m.toLowerCase()),
      cnames: split(text("cnames")).map((c) => c.toLowerCase()),
      ignore: fd.get("ignore") === "on",
      description: text("description"),
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const value = read(e.currentTarget);
    if (!value.host) return setFieldError("A host name is required");
    if (value.ips.length === 0)
      return setFieldError("At least one IP address is required");
    if (!value.description)
      return setFieldError(
        "A description is required; it identifies the entry",
      );
    if (value.ignore && value.hwaddrs.length === 0)
      return setFieldError("'Ignore' needs a MAC address to block");
    onSubmit(value);
  };

  const live = draft ?? initial;
  const changes = editing && live ? hostDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="host-name">Host name</Label>
          <Input
            id="host-name"
            name="host"
            maxLength={63}
            autoComplete="off"
            defaultValue={initial?.host}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="host-domain">Domain</Label>
          <Input
            id="host-domain"
            name="domain"
            autoComplete="off"
            defaultValue={initial?.domain}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="host-ips">IP addresses</Label>
          <Input
            id="host-ips"
            name="ips"
            autoComplete="off"
            defaultValue={initial?.ips.join(", ")}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="host-macs">MAC addresses</Label>
          <Input
            id="host-macs"
            name="hwaddrs"
            autoComplete="off"
            defaultValue={initial?.hwaddrs.join(", ")}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="host-cnames">Aliases (CNAME)</Label>
          <Input
            id="host-cnames"
            name="cnames"
            autoComplete="off"
            defaultValue={initial?.cnames.join(", ")}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="host-description">Description</Label>
          <Input
            id="host-description"
            name="description"
            maxLength={255}
            autoComplete="off"
            defaultValue={initial?.description}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Separate several values with commas. A MAC address makes DHCP always
        give that device this address. No wildcards. The description is also the
        text you type to apply a high-risk entry.
      </p>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          name="ignore"
          defaultChecked={initial?.ignore ?? false}
        />{" "}
        Ignore: refuse DHCP to these MAC addresses (high risk)
      </label>
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
      <p className="text-xs text-muted-foreground">
        Applying restarts Dnsmasq, so DNS and DHCP pause for a moment. Existing
        leases are kept.
      </p>
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
