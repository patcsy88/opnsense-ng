import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { DnsmasqDomain, DomainProposalInput } from "@/lib/schemas";

interface Props {
  initial?: DomainProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (override: DomainProposalInput) => void;
  onCancel: () => void;
}

/** The editable form of a live override, or null when it cannot be represented. */
export function toDomainProposal(d: DnsmasqDomain): DomainProposalInput | null {
  if (!d.domain || !d.server || !d.description) return null;
  const port = d.port ? Number(d.port) : null;
  if (port !== null && !Number.isInteger(port)) return null;
  return {
    domain: d.domain,
    server: d.server,
    port,
    description: d.description,
  };
}

const FIELDS: [string, (d: DomainProposalInput) => string][] = [
  ["Domain", (d) => d.domain],
  ["DNS server", (d) => d.server],
  ["Port", (d) => (d.port === null ? "" : String(d.port))],
  ["Description", (d) => d.description],
];

export function domainDiff(
  before: DomainProposalInput,
  after: DomainProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

export function DomainForm({
  initial,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<DomainProposalInput | null>(null);

  const read = (form: HTMLFormElement): DomainProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      domain: text("domain").toLowerCase(),
      server: text("server"),
      port: text("port") === "" ? null : Number(text("port")),
      description: text("description"),
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const value = read(e.currentTarget);
    if (!value.domain) return setFieldError("A domain is required");
    if (value.domain.includes("*"))
      return setFieldError("Wildcards are not allowed");
    if (!value.server)
      return setFieldError("A DNS server IP address is required");
    if (
      value.port !== null &&
      (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535)
    )
      return setFieldError("The port must be a number from 1 to 65535");
    if (!value.description)
      return setFieldError(
        "A description is required; it identifies the entry",
      );
    onSubmit(value);
  };

  const live = draft ?? initial;
  const changes = editing && live ? domainDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="dom-domain">Domain</Label>
          <Input
            id="dom-domain"
            name="domain"
            autoComplete="off"
            defaultValue={initial?.domain}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="dom-server">DNS server IP</Label>
          <Input
            id="dom-server"
            name="server"
            autoComplete="off"
            defaultValue={initial?.server}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="dom-port">Port (optional)</Label>
          <Input
            id="dom-port"
            name="port"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.port ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="dom-description">Description</Label>
          <Input
            id="dom-description"
            name="description"
            maxLength={255}
            autoComplete="off"
            defaultValue={initial?.description}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        All lookups for this domain and its subdomains go to the DNS server you
        name. A wrong or hostile server can misdirect or capture traffic, so
        every override is high risk: an admin must approve it, and the
        description is typed to apply it. No wildcards; single-label and very
        broad domains are refused.
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
