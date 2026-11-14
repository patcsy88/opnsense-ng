import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type {
  UnboundForward,
  UnboundForwardProposalInput,
} from "@/lib/schemas";

interface Props {
  initial?: UnboundForwardProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (forward: UnboundForwardProposalInput) => void;
  onCancel: () => void;
}

/** The editable form of a live forward, or null when it cannot be represented. */
export function toUnboundForwardProposal(
  f: UnboundForward,
): UnboundForwardProposalInput | null {
  if (!f.domain || !f.server || !f.description) return null;
  const port = f.port ? Number(f.port) : null;
  if (port !== null && !Number.isInteger(port)) return null;
  return {
    domain: f.domain,
    server: f.server,
    port,
    description: f.description,
    enabled: f.enabled,
  };
}

const FIELDS: [string, (f: UnboundForwardProposalInput) => string][] = [
  ["Domain", (f) => f.domain],
  ["DNS server", (f) => f.server],
  ["Port", (f) => (f.port === null ? "" : String(f.port))],
  ["Description", (f) => f.description],
];

export function unboundForwardDiff(
  before: UnboundForwardProposalInput,
  after: UnboundForwardProposalInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

export function UnboundForwardForm({
  initial,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<UnboundForwardProposalInput | null>(null);

  const read = (form: HTMLFormElement): UnboundForwardProposalInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      domain: text("domain").toLowerCase(),
      server: text("server"),
      port: text("port") === "" ? null : Number(text("port")),
      description: text("description"),
      enabled: initial?.enabled ?? true,
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const value = read(e.currentTarget);
    if (!value.domain)
      return setFieldError(
        "A domain is required; an empty domain would redirect all DNS",
      );
    if (value.domain.includes("*"))
      return setFieldError("Wildcards are not allowed");
    if (!value.domain.includes("."))
      return setFieldError(
        "Use a domain with at least two labels, such as corp.example",
      );
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
  const changes = editing && live ? unboundForwardDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label htmlFor="uf-domain">Domain</Label>
          <Input
            id="uf-domain"
            name="domain"
            autoComplete="off"
            defaultValue={initial?.domain}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uf-server">DNS server IP</Label>
          <Input
            id="uf-server"
            name="server"
            autoComplete="off"
            defaultValue={initial?.server}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uf-port">Port (optional)</Label>
          <Input
            id="uf-port"
            name="port"
            inputMode="numeric"
            autoComplete="off"
            defaultValue={initial?.port ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="uf-description">Description</Label>
          <Input
            id="uf-description"
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
        every forward change is high risk: an admin must approve it, and the
        description is typed to apply it. Applying restarts Unbound, so DNS
        pauses for every client. No wildcards; single-label and very broad
        domains are refused.
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
