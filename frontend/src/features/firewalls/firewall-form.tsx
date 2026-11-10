import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { firewallCreateFormSchema, type Firewall, type FirewallCreateInput, type FirewallUpdateInput } from "@/lib/schemas";

interface Props {
  /** When set, the form edits this firewall via PATCH; secrets stay blank unless replaced. */
  firewall?: Firewall;
  pending: boolean;
  error: string | null;
  onSubmit: (payload: FirewallCreateInput | FirewallUpdateInput) => Promise<void>;
  onCancel: () => void;
}

export function FirewallForm({ firewall, pending, error, onSubmit, onCancel }: Props) {
  const editing = firewall !== undefined;
  const [verifyTls, setVerifyTls] = useState(firewall?.verify_tls ?? true);
  const [removeCa, setRemoveCa] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);

  const handle = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const formEl = e.currentTarget;
    const fd = new FormData(formEl);
    const str = (k: string) => String(fd.get(k) ?? "");
    const name = str("name").trim();
    const base_url = str("base_url").trim();
    const api_key = str("api_key");
    const api_secret = str("api_secret");
    const ca = str("ca_bundle_pem").trim();

    let payload: FirewallCreateInput | FirewallUpdateInput;
    if (!editing) {
      const parsed = firewallCreateFormSchema.safeParse({ name, base_url, api_key, api_secret });
      if (!parsed.success) {
        setFieldError(parsed.error.issues[0]?.message ?? "Invalid input");
        return;
      }
      payload = { ...parsed.data, verify_tls: verifyTls, ...(ca ? { ca_bundle_pem: ca } : {}) };
    } else {
      if ((api_key && !api_secret) || (!api_key && api_secret)) {
        setFieldError("Provide both API key and secret to replace credentials");
        return;
      }
      const p: FirewallUpdateInput = {};
      if (name && name !== firewall.name) p.name = name;
      if (base_url && base_url !== firewall.base_url) p.base_url = base_url;
      if (verifyTls !== firewall.verify_tls) p.verify_tls = verifyTls;
      if (api_key) {
        p.api_key = api_key;
        p.api_secret = api_secret;
      }
      if (removeCa) p.ca_bundle_pem = "";
      else if (ca) p.ca_bundle_pem = ca;
      payload = p;
    }
    try {
      await onSubmit(payload);
    } finally {
      // Secrets are write-only: wipe the DOM fields whether or not the request succeeded.
      formEl.reset();
    }
  };

  return (
    <form onSubmit={(e) => void handle(e)} className="space-y-3" autoComplete="off" noValidate>
      <div className="space-y-1">
        <Label htmlFor="fw-name">Name</Label>
        <Input id="fw-name" name="name" defaultValue={firewall?.name ?? ""} maxLength={100} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="fw-url">Base URL</Label>
        <Input id="fw-url" name="base_url" placeholder="https://192.0.2.1" defaultValue={firewall?.base_url ?? ""} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="fw-key">API key{editing && " (leave blank to keep)"}</Label>
        <Input id="fw-key" name="api_key" type="password" autoComplete="off" />
      </div>
      <div className="space-y-1">
        <Label htmlFor="fw-secret">API secret{editing && " (leave blank to keep)"}</Label>
        <Input id="fw-secret" name="api_secret" type="password" autoComplete="off" />
      </div>
      <div className="space-y-1">
        <Label htmlFor="fw-ca">
          CA bundle (PEM, optional){editing && firewall.has_ca_bundle ? " — a bundle is stored" : ""}
        </Label>
        <Textarea id="fw-ca" name="ca_bundle_pem" placeholder="-----BEGIN CERTIFICATE-----" />
        {editing && firewall.has_ca_bundle && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={removeCa} onChange={(e) => setRemoveCa(e.target.checked)} />
            Remove stored CA bundle
          </label>
        )}
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} />
        Verify TLS certificate
      </label>
      {!verifyTls && (
        <p role="alert" className="rounded-md border border-warning/50 bg-warning/10 p-2 text-sm text-warning">
          Warning: with certificate verification off, the connection to this firewall can be intercepted
          and the API credentials exposed. Prefer providing a CA bundle. The server may refuse this setting.
        </p>
      )}
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
          {pending ? "Saving…" : editing ? "Save changes" : "Add firewall"}
        </Button>
      </DialogFooter>
    </form>
  );
}
