import { Loading } from "@/components/ui/loading";
import { Tabs, TabsList, TabsTab } from "@/components/ui/tabs";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { UnverifiedBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ChangeStatusBadge } from "@/features/changes/status";
import {
  KeaReservationForm,
  toKeaReservationProposal,
} from "@/features/changes/kea-reservation-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { KeaReservation, KeaReservationInput } from "@/lib/schemas";

type Section = "leases" | "reservations" | "subnets";

function when(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function Panel({
  title,
  description,
  verified,
  loading,
  error,
  onRetry,
  empty,
  action,
  before,
  children,
}: {
  title: string;
  description: string;
  verified: boolean | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  empty: boolean;
  action?: React.ReactNode;
  before?: React.ReactNode;
  children: React.ReactNode;
}) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex flex-wrap items-center gap-2">
            {title} {verified === false && <UnverifiedBadge />}
          </span>
          {action}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {before}
        {loading ? (
          <Loading />
        ) : empty ? (
          <p className="text-sm text-muted-foreground">Nothing to show.</p>
        ) : (
          <Table>{children}</Table>
        )}
      </CardContent>
    </Card>
  );
}

function Leases({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["firewalls", id, "kea-leases"],
    queryFn: () => api.keaLeases(id),
    refetchInterval: 30_000,
  });
  return (
    <Panel
      title="Kea leases"
      description="Read-only. MAC addresses are not shown."
      verified={q.data?.registry_verified}
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      empty={q.data?.leases.length === 0}
    >
      <TableHeader>
        <TableRow>
          <TableHead>Address</TableHead>
          <TableHead>Hostname</TableHead>
          <TableHead>Interface</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Expires</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {q.data?.leases.map((l, i) => (
          <TableRow key={`${l.address}-${i}`}>
            <TableCell className="font-mono text-xs sm:text-sm">
              {l.address}
            </TableCell>
            <TableCell>{l.hostname ?? "—"}</TableCell>
            <TableCell>{l.interface ?? "—"}</TableCell>
            <TableCell>{l.state ?? "—"}</TableCell>
            <TableCell>{when(l.expires)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Panel>
  );
}

const OPEN = new Set(["draft", "validated", "in_review", "approved"]);

function Reservations({ id }: { id: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<KeaReservation | null>(null);
  const [deleting, setDeleting] = useState<KeaReservation | null>(null);
  const [pending, setPending] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["firewalls", id, "kea-reservations"],
    queryFn: () => api.keaReservations(id),
  });
  const subnets = useQuery({
    queryKey: ["firewalls", id, "kea-subnets"],
    queryFn: () => api.keaSubnets(id),
  });
  const changes = useQuery({
    queryKey: ["changes", "list", id],
    queryFn: () => api.listChanges({ firewallId: id }),
  });
  const open = (changes.data ?? []).filter(
    (c) => c.kind === "kea_reservation" && OPEN.has(c.status),
  );

  const close = () => {
    setCreating(false);
    setEditing(null);
    setDeleting(null);
    setChangeError(null);
  };
  const stage = (run: () => Promise<{ id: string }>) => {
    setChangeError(null);
    setPending(true);
    run()
      .then(async (made) => {
        await qc.invalidateQueries({ queryKey: ["changes"] });
        close();
        navigate(`/administration/changes/${made.id}`);
      })
      .catch((e: unknown) => setChangeError(describeError(e).message))
      .finally(() => setPending(false));
  };
  const editable = editing ? toKeaReservationProposal(editing) : null;
  const subnetList = subnets.data?.subnets ?? [];

  return (
    <div className="space-y-4">
      <Panel
        title="Kea reservations"
        description="Visible to administrators and network administrators. Changes are requests: nothing is sent until they are reviewed, approved and applied, and applying may restart Kea."
        verified={q.data?.registry_verified}
        loading={q.isPending}
        error={q.error}
        onRetry={() => void q.refetch()}
        empty={q.data?.reservations.length === 0}
        action={
          <Button
            size="sm"
            disabled={subnetList.length === 0}
            onClick={() => setCreating(true)}
          >
            <Plus className="mr-1 h-4 w-4" aria-hidden /> New reservation
          </Button>
        }
        before={
          open.length > 0 && (
            <div className="mb-3 rounded-md border border-border p-2 text-sm">
              <p className="font-medium">Open requests</p>
              <ul className="mt-1 space-y-1">
                {open.map((c) => (
                  <li key={c.id} className="flex items-center gap-2">
                    <ChangeStatusBadge status={c.status} />
                    <Link
                      className="text-primary underline"
                      to={`/administration/changes/${c.id}`}
                    >
                      {c.action} {String(c.proposed?.label ?? "reservation")}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )
        }
      >
        <TableHeader>
          <TableRow>
            <TableHead>IP address</TableHead>
            <TableHead>Subnet</TableHead>
            <TableHead>MAC address</TableHead>
            <TableHead>Hostname</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {q.data?.reservations.map((r) => (
            <TableRow key={r.uuid}>
              <TableCell className="font-mono text-xs sm:text-sm">
                {r.ip_address}
              </TableCell>
              <TableCell className="font-mono text-xs sm:text-sm">
                {r.subnet ?? "—"}
              </TableCell>
              <TableCell className="font-mono text-xs sm:text-sm">
                {r.hw_address ?? "—"}
              </TableCell>
              <TableCell>{r.hostname ?? "—"}</TableCell>
              <TableCell>{r.description ?? "—"}</TableCell>
              <TableCell className="space-x-2">
                {toKeaReservationProposal(r) && (
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={`Edit ${r.ip_address}`}
                    onClick={() => setEditing(r)}
                  >
                    <Pencil className="h-4 w-4" aria-hidden />
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  aria-label={`Delete ${r.ip_address}`}
                  onClick={() => setDeleting(r)}
                >
                  <Trash2 className="h-4 w-4" aria-hidden />
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Panel>

      <Dialog
        open={creating || editable !== null}
        onOpenChange={(o) => !o && close()}
      >
        <DialogContent className="p-6">
          <DialogHeader className="p-0 pb-3">
            <DialogTitle>
              {editing
                ? `Change reservation ${editing.ip_address}`
                : "New Kea reservation"}
            </DialogTitle>
            <DialogDescription>
              Creates a change request. Nothing is sent to the firewall until it
              is reviewed, approved and applied.
            </DialogDescription>
          </DialogHeader>
          <KeaReservationForm
            subnets={subnetList}
            initial={editable ?? undefined}
            pending={pending}
            error={changeError}
            onCancel={close}
            onSubmit={(value: KeaReservationInput) => {
              if (editing)
                stage(() =>
                  api.stageKeaReservationUpdate(id, editing.uuid, value),
                );
              else stage(() => api.stageKeaReservation(id, value));
            }}
          />
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && close()}
        title="Request deleting this reservation?"
        confirmLabel="Create change request"
        destructive
        pending={pending}
        error={changeError}
        description={
          <>
            This creates a high-risk change request to delete the reservation
            for <strong>{deleting?.ip_address}</strong>. The device loses its
            fixed address. Nothing is sent to the firewall until an admin
            approves it and applies it by typing the IP address. Kea may restart
            and DHCP may pause briefly.
          </>
        }
        onConfirm={() => {
          if (!deleting) return;
          const target = deleting;
          stage(() => api.stageKeaReservationDelete(id, target.uuid));
        }}
      />
    </div>
  );
}

function Subnets({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["firewalls", id, "kea-subnets"],
    queryFn: () => api.keaSubnets(id),
  });
  return (
    <Panel
      title="Kea subnets"
      description="Read-only."
      verified={q.data?.registry_verified}
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      empty={q.data?.subnets.length === 0}
    >
      <TableHeader>
        <TableRow>
          <TableHead>Subnet</TableHead>
          <TableHead>Pools</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {q.data?.subnets.map((s) => (
          <TableRow key={s.uuid}>
            <TableCell className="font-mono text-xs sm:text-sm">
              {s.subnet}
            </TableCell>
            <TableCell className="font-mono text-xs sm:text-sm">
              {s.pools.length ? s.pools.join(", ") : "—"}
            </TableCell>
            <TableCell>{s.description ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Panel>
  );
}

export function KeaTab({
  firewallId,
  canManage,
}: {
  firewallId: string;
  canManage: boolean;
}) {
  const [section, setSection] = useState<Section>("leases");
  const sections: [Section, string][] = [
    ["leases", "Leases"],
    ...(canManage
      ? ([["reservations", "Reservations"]] as [Section, string][])
      : []),
    ["subnets", "Subnets"],
  ];
  const shown = sections.some(([s]) => s === section) ? section : "leases";
  return (
    <>
      <Tabs value={shown} onValueChange={(v) => setSection(v as typeof section)}>
        <TabsList aria-label="Kea section">
          {sections.map(([id, text]) => (
            <TabsTab key={id} value={id}>
              {text}
            </TabsTab>
          ))}
        </TabsList>
      </Tabs>
      {shown === "leases" && <Leases id={firewallId} />}
      {shown === "reservations" && <Reservations id={firewallId} />}
      {shown === "subnets" && <Subnets id={firewallId} />}
    </>
  );
}
