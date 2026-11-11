import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ALIAS_TYPES, type AliasProposalInput } from "@/lib/schemas";

interface Props {
  /** When set the form edits this alias: name and type are fixed. */
  initial?: AliasProposalInput;
  pending: boolean;
  error: string | null;
  onSubmit: (alias: AliasProposalInput) => void;
  onCancel: () => void;
}

const HINTS: Record<(typeof ALIAS_TYPES)[number], string> = {
  host: "One IP address or hostname per line",
  network: "One network per line, e.g. 10.0.0.0/24",
  port: "One port or range per line, e.g. 443 or 8000:8100",
};

export function AliasForm({ initial, pending, error, onSubmit, onCancel }: Props) {
  const editing = initial !== undefined;
  const [type, setType] = useState<(typeof ALIAS_TYPES)[number]>(initial?.type ?? "host");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [fieldError, setFieldError] = useState<string | null>(null);

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get("name") ?? "").trim();
    const content = String(fd.get("content") ?? "")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (!name) return setFieldError("Name is required");
    if (content.length === 0) return setFieldError("Add at least one entry");
    onSubmit({
      name,
      type,
      content,
      description: String(fd.get("description") ?? "").trim(),
      ...(editing ? { enabled } : {}),
    });
  };

  return (
    <form onSubmit={handle} className="space-y-3" noValidate>
      <div className="space-y-1">
        <Label htmlFor="alias-name">Name</Label>
        <Input
          id="alias-name"
          name="name"
          maxLength={32}
          autoComplete="off"
          defaultValue={initial?.name ?? ""}
          readOnly={editing}
        />
        <p className="text-xs text-muted-foreground">
          Letters, digits and underscores, starting with a letter or underscore (max 32).
        </p>
      </div>
      <div className="space-y-1">
        <Label htmlFor="alias-type">Type</Label>
        <select
          id="alias-type"
          className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
          value={type}
          disabled={editing}
          onChange={(e) => setType(e.target.value as (typeof ALIAS_TYPES)[number])}
        >
          {ALIAS_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="alias-content">Content</Label>
        <Textarea
          id="alias-content"
          name="content"
          spellCheck={false}
          defaultValue={initial?.content.join("\n") ?? ""}
        />
        <p className="text-xs text-muted-foreground">{HINTS[type]}</p>
      </div>
      <div className="space-y-1">
        <Label htmlFor="alias-description">Description (optional)</Label>
        <Input
          id="alias-description"
          name="description"
          maxLength={255}
          defaultValue={initial?.description ?? ""}
        />
      </div>
      <div className="space-y-1">
        {editing && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled
          </label>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        This creates a change request only. Nothing is sent to the firewall until the request is
        reviewed, approved and applied by an administrator.
      </p>
      {(fieldError ?? error) && (
        <p role="alert" className="text-sm text-destructive">
          {fieldError ?? error}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : editing ? "Create change request" : "Create request"}
        </Button>
      </DialogFooter>
    </form>
  );
}
