import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { UnboundHost, UnboundHostProposalInput } from "@/lib/schemas";

interface Props {
  initial?: UnboundHostProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (host: UnboundHostProposalInput) => void;
  onCancel: () => void;
}

/** The editable form of a live host override, or null when it cannot be represented. */
export function toUnboundProposal(
  h: UnboundHost,
): UnboundHostProposalInput | null {
  if (!h.editable || !h.hostname || !h.domain || !h.server || !h.description)
    return null;
  if (h.rr !== "A" && h.rr !== "AAAA") return null;
  const ttl = h.ttl ? Number(h.ttl) : null;
  if (ttl !== null && !Number.isInteger(ttl)) return null;
  return {
    hostname: h.hostname,
    domain: h.domain,
    rr: h.rr,
    server: h.server,
    ttl,
    description: h.description,
    enabled: h.enabled,
  };
}

const FIELDS: [string, (h: UnboundHostProposalInput) => string][] = [
  ["Host name", (h) => h.hostname],
  ["Domain", (h) => h.domain],
  ["Record type", (h) => h.rr],
  ["IP address", (h) => h.server],
  ["TTL", (h) => (h.ttl === null ? "" : String(h.ttl))],
  ["Description", (h) => h.description],
];

export function unboundHostDiff(
  before: UnboundHostProposalInput,
  after: UnboundHostProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

export function UnboundHostForm({
  initial,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<UnboundHostProposalInput | null>(null);

  const read = (form: HTMLFormElement): UnboundHostProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      hostname: text("hostname").toLowerCase(),
      domain: text("domain").toLowerCase(),
      rr: text("rr") === "AAAA" ? "AAAA" : "A",
      server: text("server"),
      ttl: text("ttl") === "" ? null : Number(text("ttl")),
      description: text("description"),
      enabled: initial?.enabled ?? true,
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const value = read(e.currentTarget);
    if (!value.hostname) return setFieldError("A host name is required");
    if (value.hostname.includes("*") || value.hostname.includes(".")) {
      return setFieldError(
        "The host name is a single label without wildcards; put the rest in Domain",
      );
    }
    if (!value.domain) return setFieldError("A domain is required");
    if (!value.server) return setFieldError("An IP address is required");
    if (value.ttl !== null && (!Number.isInteger(value.ttl) || value.ttl < 0))
      return setFieldError("The TTL must be a whole number of seconds");
    if (!value.description)
      return setFieldError(
        "A description is required; it identifies the entry",
      );
    onSubmit(value);
  };

  const live = draft ?? initial;
  const changes = editing && live ? unboundHostDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="uh-hostname">Host name</Label>
          <Input
            id="uh-hostname"
            name="hostname"
            maxLength={63}
            autoComplete="off"
            defaultValue={initial?.hostname}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uh-domain">Domain</Label>
          <Input
            id="uh-domain"
            name="domain"
            autoComplete="off"
            defaultValue={initial?.domain}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uh-rr">Record type</Label>
          <select
            id="uh-rr"
            name="rr"
            defaultValue={initial?.rr ?? "A"}
            className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
          >
            <option value="A">A (IPv4)</option>
            <option value="AAAA">AAAA (IPv6)</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="uh-server">IP address</Label>
          <Input
            id="uh-server"
            name="server"
            autoComplete="off"
            defaultValue={initial?.server}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uh-ttl">TTL seconds (optional)</Label>
          <Input
            id="uh-ttl"
            name="ttl"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.ttl ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uh-description">Description</Label>
          <Input
            id="uh-description"
            name="description"
            maxLength={255}
            autoComplete="off"
            defaultValue={initial?.description}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Only A and AAAA records are managed here. Applying restarts Unbound, so
        DNS pauses for every client for a moment. Using the firewall&apos;s own
        name or address makes the request high risk.
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
