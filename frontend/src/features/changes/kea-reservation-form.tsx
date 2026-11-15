import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type {
  KeaReservation,
  KeaReservationInput,
  KeaSubnet,
} from "@/lib/schemas";

const SELECT =
  "h-9 w-full rounded-md border border-border bg-card px-2 text-sm";
const MAC = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

interface Props {
  subnets: KeaSubnet[];
  initial?: KeaReservationInput;
  pending: boolean;
  error: string | null;
  onSubmit: (reservation: KeaReservationInput) => void;
  onCancel: () => void;
}

/** The editable form of a live reservation, or null when it cannot be represented. */
export function toKeaReservationProposal(
  r: KeaReservation,
): KeaReservationInput | null {
  if (!r.subnet_id || !r.hw_address) return null;
  return {
    subnet: r.subnet_id,
    ip_address: r.ip_address,
    hw_address: r.hw_address,
    hostname: r.hostname,
    description: r.description,
  };
}

const FIELDS: [string, (d: KeaReservationInput) => string][] = [
  ["IP address", (d) => d.ip_address],
  ["MAC address", (d) => d.hw_address.toLowerCase()],
  ["Hostname", (d) => d.hostname ?? ""],
  ["Description", (d) => d.description ?? ""],
];

export function keaReservationDiff(
  before: KeaReservationInput,
  after: KeaReservationInput,
): [string, string, string][] {
  return FIELDS.flatMap(([label, get]) => {
    const [a, b] = [get(before), get(after)];
    return a === b
      ? []
      : [[label, a || "—", b || "—"] as [string, string, string]];
  });
}

function toNumber(ip: string): number | null {
  const m = IPV4.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return parts.reduce((acc, n) => acc * 256 + n, 0);
}

/** A problem with the IP for this subnet, or null. The backend checks again. */
export function ipProblem(ip: string, subnet: KeaSubnet): string | null {
  const addr = toNumber(ip);
  if (addr === null) return "Enter a valid IPv4 address";
  const [base = "", bits] = subnet.subnet.split("/");
  const start = toNumber(base);
  const prefix = Number(bits);
  if (start === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32)
    return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if ((addr & mask) >>> 0 !== (start & mask) >>> 0)
    return `The IP address is outside the subnet ${subnet.subnet}`;
  for (const line of subnet.pools) {
    const [a, b] = line.split("-").map((x) => toNumber(x.trim()));
    if (a != null && b != null && addr >= a && addr <= b)
      return "The IP address lies inside a dynamic pool of this subnet";
  }
  return null;
}

export function KeaReservationForm({
  subnets,
  initial,
  pending,
  error,
  onSubmit,
  onCancel,
}: Props) {
  const editing = initial !== undefined;
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [draft, setDraft] = useState<KeaReservationInput | null>(null);

  const read = (form: HTMLFormElement): KeaReservationInput => {
    const fd = new FormData(form);
    const text = (k: string) => String(fd.get(k) ?? "").trim();
    return {
      subnet: text("subnet"),
      ip_address: text("ip_address"),
      hw_address: text("hw_address").toLowerCase().replaceAll("-", ":"),
      hostname: text("hostname").toLowerCase() || null,
      description: text("description") || null,
    };
  };

  const handle = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFieldError(null);
    const value = read(e.currentTarget);
    const subnet = subnets.find((s) => s.uuid === value.subnet);
    if (!subnet) return setFieldError("Choose a subnet");
    const problem = ipProblem(value.ip_address, subnet);
    if (problem) return setFieldError(problem);
    if (!MAC.test(value.hw_address))
      return setFieldError("MAC addresses look like aa:bb:cc:dd:ee:ff");
    onSubmit(value);
  };

  const live = draft ?? initial;
  const changes = editing && live ? keaReservationDiff(initial, live) : [];

  return (
    <form
      onSubmit={handle}
      onChange={(e) => setDraft(read(e.currentTarget))}
      className="space-y-3"
      noValidate
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 space-y-1">
          <Label htmlFor="kea-subnet">Subnet</Label>
          <select
            id="kea-subnet"
            name="subnet"
            className={SELECT}
            defaultValue={initial?.subnet ?? subnets[0]?.uuid ?? ""}
          >
            {subnets.map((s) => (
              <option key={s.uuid} value={s.uuid}>
                {s.subnet}
                {s.description ? ` (${s.description})` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="kea-ip">IP address</Label>
          <Input
            id="kea-ip"
            name="ip_address"
            autoComplete="off"
            defaultValue={initial?.ip_address}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kea-mac">MAC address</Label>
          <Input
            id="kea-mac"
            name="hw_address"
            autoComplete="off"
            defaultValue={initial?.hw_address}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kea-hostname">Hostname (optional)</Label>
          <Input
            id="kea-hostname"
            name="hostname"
            autoComplete="off"
            defaultValue={initial?.hostname ?? ""}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kea-description">Description (optional)</Label>
          <Input
            id="kea-description"
            name="description"
            maxLength={255}
            autoComplete="off"
            defaultValue={initial?.description ?? ""}
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        The address must be inside the subnet and outside its dynamic pools.
        Deleting a reservation, or changing its MAC or IP address, is high risk:
        an admin must approve it, and the IP address is typed to apply it.
        Applying may restart Kea, so DHCP may pause briefly.
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
