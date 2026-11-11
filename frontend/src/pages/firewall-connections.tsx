import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { useState } from "react";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FirewallForm } from "@/features/firewalls/firewall-form";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import type { Firewall, FirewallCreateInput, FirewallUpdateInput } from "@/lib/schemas";

type Editing = { mode: "create" } | { mode: "edit"; firewall: Firewall } | null;

export function FirewallConnectionsPage() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["firewalls"], queryFn: api.listFirewalls });
  const [editing, setEditing] = useState<Editing>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [tlsConfirm, setTlsConfirm] = useState<Firewall | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<Firewall | null>(null);

  // Deliberately not useMutation: its cache would retain the submitted variables (API key/secret).
  const [saving, setSaving] = useState(false);

  // High-impact: turning TLS verification off (the closest the API gets to "disable").
  const disableTls = useMutation({
    mutationFn: (id: string) => api.updateFirewall(id, { verify_tls: false }),
    onSuccess: () => {
      setTlsConfirm(null);
      return qc.invalidateQueries({ queryKey: ["firewalls"] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteFirewall(id),
    onSuccess: async () => {
      setDeleteConfirm(null);
      await qc.invalidateQueries({ queryKey: ["firewalls"] });
    },
  });

  const submit = async (payload: FirewallCreateInput | FirewallUpdateInput) => {
    setFormError(null);
    setSaving(true);
    try {
      if (editing?.mode === "edit") {
        await api.updateFirewall(editing.firewall.id, payload as FirewallUpdateInput);
      } else {
        await api.createFirewall(payload as FirewallCreateInput);
      }
      await qc.invalidateQueries({ queryKey: ["firewalls"] });
      setEditing(null);
    } catch (e) {
      setFormError(describeError(e).message);
    } finally {
      setSaving(false);
    }
  };

  const close = () => {
    setEditing(null);
    setFormError(null);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Firewall Connections</h1>
        <Button onClick={() => setEditing({ mode: "create" })}>
          <Plus className="h-4 w-4" /> Add firewall
        </Button>
      </div>

      <Card>
        <CardContent className="pt-4">
          {list.isPending ? (
            <p role="status" className="text-sm text-muted-foreground">Loading…</p>
          ) : list.isError ? (
            <ErrorState error={list.error} onRetry={() => void list.refetch()} />
          ) : list.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">No firewall connections yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Base URL</TableHead>
                  <TableHead>TLS</TableHead>
                  <TableHead>CA bundle</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.data.map((fw) => (
                  <TableRow key={fw.id}>
                    <TableCell className="font-medium">{fw.name}</TableCell>
                    <TableCell className="font-mono text-xs">{fw.base_url}</TableCell>
                    <TableCell>
                      {fw.verify_tls ? (
                        <Badge variant="success">Verified</Badge>
                      ) : (
                        <Badge variant="warning">
                          <ShieldAlert className="h-3 w-3" aria-hidden /> Not verified
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{fw.has_ca_bundle ? "Yes" : "No"}</TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button size="sm" variant="outline" onClick={() => setEditing({ mode: "edit", firewall: fw })}>
                        <Pencil className="h-3 w-3" /> Edit
                      </Button>
                      {fw.verify_tls && (
                        <Button size="sm" variant="ghost" onClick={() => setTlsConfirm(fw)}>
                          Disable TLS check
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" onClick={() => setDeleteConfirm(fw)}>
                        <Trash2 className="h-3 w-3" /> Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            Credentials are write-only and never shown.
          </p>
        </CardContent>
      </Card>

      <Dialog open={editing !== null} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing?.mode === "edit" ? "Edit firewall" : "Add firewall"}</DialogTitle>
            <DialogDescription>Credentials are encrypted by the backend and cannot be read back.</DialogDescription>
          </DialogHeader>
          {editing && (
            <FirewallForm
              key={editing.mode === "edit" ? editing.firewall.id : "new"}
              firewall={editing.mode === "edit" ? editing.firewall : undefined}
              pending={saving}
              error={formError}
              onSubmit={submit}
              onCancel={close}
            />
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={tlsConfirm !== null}
        onOpenChange={(o) => {
          if (!o) {
            setTlsConfirm(null);
            disableTls.reset();
          }
        }}
        title="Disable TLS verification?"
        destructive
        confirmLabel="Disable verification"
        requireText={tlsConfirm?.name}
        pending={disableTls.isPending}
        error={disableTls.isError ? describeError(disableTls.error).message : null}
        description={
          <>
            Connections to <strong>{tlsConfirm?.name}</strong> will no longer verify the certificate, which
            exposes API credentials to interception.
          </>
        }
        onConfirm={() => tlsConfirm && disableTls.mutate(tlsConfirm.id)}
      />

      <ConfirmDialog
        open={deleteConfirm !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDeleteConfirm(null);
            remove.reset();
          }
        }}
        title="Delete firewall connection?"
        destructive
        confirmLabel="Delete connection"
        requireText={deleteConfirm?.name}
        pending={remove.isPending}
        error={remove.isError ? describeError(remove.error).message : null}
        description={
          <>
            The connection to <strong>{deleteConfirm?.name}</strong> and its stored credentials will be
            removed. The firewall itself is not changed. Audit history is kept.
          </>
        }
        onConfirm={() => deleteConfirm && remove.mutate(deleteConfirm.id)}
      />
    </div>
  );
}
