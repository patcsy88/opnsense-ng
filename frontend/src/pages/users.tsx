import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { Badge } from "@/components/ui/badge";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { ROLES, type Role, type UserRow } from "@/lib/schemas";

const USERS_KEY = ["users"] as const;

interface Issued {
  username: string;
  password: string;
  heading: string;
}

type Pending = {
  kind: "deactivate" | "reactivate" | "reset-password" | "reset-mfa";
  user: UserRow;
};

export function UsersPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: USERS_KEY, queryFn: () => api.listUsers() });
  const [pending, setPending] = useState<Pending | null>(null);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [copied, setCopied] = useState(false);
  const [rowError, setRowError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newRole, setNewRole] = useState<Role>("read_only");

  const refresh = () => qc.invalidateQueries({ queryKey: USERS_KEY });
  const closePending = () => setPending(null);

  const create = useMutation({
    mutationFn: () => api.createUser(newName.trim(), newRole),
    onSuccess: async (res) => {
      setIssued({
        username: res.user.username,
        password: res.temporary_password,
        heading: "User created",
      });
      setNewName("");
      await refresh();
    },
  });

  const role = useMutation({
    mutationFn: (v: { id: string; role: Role }) =>
      api.changeUserRole(v.id, v.role),
    onSuccess: async () => {
      setRowError(null);
      await refresh();
    },
    onError: (e) => setRowError(describeError(e).message),
  });

  const toggle = useMutation({
    mutationFn: (v: Pending) =>
      v.kind === "deactivate"
        ? api.deactivateUser(v.user.id)
        : api.reactivateUser(v.user.id),
    onSuccess: async () => {
      setRowError(null);
      closePending();
      await refresh();
    },
  });

  const reset = useMutation({
    mutationFn: (v: Pending) => api.resetUserPassword(v.user.id),
    onSuccess: async (res) => {
      closePending();
      setIssued({
        username: res.user.username,
        password: res.temporary_password,
        heading: "Password reset",
      });
      await refresh();
    },
  });

  const mfa = useMutation({
    mutationFn: (v: { id: string; password: string; code?: string }) =>
      api.resetUserMfa(v.id, v.password, v.code),
    onSuccess: async () => {
      closePending();
      await refresh();
    },
  });

  const submitCreate = (e: FormEvent) => {
    e.preventDefault();
    if (newName.trim()) create.mutate();
  };

  const submitMfa = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!pending) return;
    const data = new FormData(e.currentTarget);
    const password = String(data.get("password") ?? "");
    const code = String(data.get("code") ?? "").trim();
    if (password)
      mfa.mutate({ id: pending.user.id, password, code: code || undefined });
  };

  const copy = async () => {
    if (!issued) return;
    await navigator.clipboard?.writeText(issued.password);
    setCopied(true);
  };

  const closeIssued = () => {
    setIssued(null);
    setCopied(false);
  };

  const users = q.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Users</h1>
        <Link className="text-sm text-primary underline" to="/administration">
          Back to Administration
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Create user</CardTitle>
          <CardDescription>
            A temporary password is generated and shown once. The user must
            change it at first sign-in.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={submitCreate}
            className="flex flex-wrap items-end gap-3"
          >
            <label className="space-y-1 text-sm">
              Username
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label className="space-y-1 text-sm">
              Role
              <select
                className="h-9 w-full rounded-md border border-border bg-card px-2"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as Role)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <Button
              type="submit"
              disabled={create.isPending || !newName.trim()}
            >
              Create user
            </Button>
          </form>
          {create.isError && (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {describeError(create.error).message}
            </p>
          )}
        </CardContent>
      </Card>

      {q.isError && (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      )}

      {!q.isError && (
        <Card>
          <CardHeader>
            <CardTitle>Accounts</CardTitle>
            <CardDescription>
              Changing a role, deactivating, or resetting a password or MFA
              signs the user out everywhere.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {rowError && (
              <p role="alert" className="text-sm text-destructive">
                {rowError}
              </p>
            )}
            {q.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading…
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>MFA</TableHead>
                    <TableHead>Sessions</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell className="font-medium">
                        {u.username}
                      </TableCell>
                      <TableCell>
                        <select
                          aria-label={`Role for ${u.username}`}
                          className="h-8 rounded-md border border-border bg-card px-2 text-sm"
                          value={u.role}
                          disabled={role.isPending}
                          onChange={(e) =>
                            role.mutate({
                              id: u.id,
                              role: e.target.value as Role,
                            })
                          }
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      </TableCell>
                      <TableCell className="space-x-1">
                        <Badge variant={u.is_active ? "success" : "warning"}>
                          {u.is_active ? "Active" : "Inactive"}
                        </Badge>
                        {u.must_change_password && (
                          <Badge variant="warning">Temporary password</Badge>
                        )}
                      </TableCell>
                      <TableCell>{u.mfa_enabled ? "On" : "Off"}</TableCell>
                      <TableCell>{u.sessions}</TableCell>
                      <TableCell>
                        {new Date(u.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="space-x-1 whitespace-nowrap">
                        {u.is_active ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              setPending({ kind: "deactivate", user: u })
                            }
                          >
                            Deactivate
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              setPending({ kind: "reactivate", user: u })
                            }
                          >
                            Reactivate
                          </Button>
                        )}
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            setPending({ kind: "reset-password", user: u })
                          }
                        >
                          Reset password
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!u.mfa_enabled}
                          onClick={() =>
                            setPending({ kind: "reset-mfa", user: u })
                          }
                        >
                          Reset MFA
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={pending?.kind === "deactivate" || pending?.kind === "reactivate"}
        onOpenChange={(o) => {
          if (!o) {
            closePending();
            toggle.reset();
          }
        }}
        title={
          pending?.kind === "reactivate"
            ? "Reactivate user?"
            : "Deactivate user?"
        }
        destructive={pending?.kind === "deactivate"}
        confirmLabel={
          pending?.kind === "reactivate" ? "Reactivate" : "Deactivate"
        }
        pending={toggle.isPending}
        error={toggle.isError ? describeError(toggle.error).message : null}
        description={
          pending?.kind === "reactivate" ? (
            <>
              <strong>{pending.user.username}</strong> will be able to sign in
              again.
            </>
          ) : (
            <>
              <strong>{pending?.user.username}</strong> will be signed out and
              unable to sign in until reactivated.
            </>
          )
        }
        onConfirm={() => pending && toggle.mutate(pending)}
      />

      <ConfirmDialog
        open={pending?.kind === "reset-password"}
        onOpenChange={(o) => {
          if (!o) {
            closePending();
            reset.reset();
          }
        }}
        title="Reset password?"
        destructive
        confirmLabel="Reset password"
        pending={reset.isPending}
        error={reset.isError ? describeError(reset.error).message : null}
        description={
          <>
            <strong>{pending?.user.username}</strong> will be signed out and
            given a new temporary password, shown once.
          </>
        }
        onConfirm={() => pending && reset.mutate(pending)}
      />

      <Dialog
        open={pending?.kind === "reset-mfa"}
        onOpenChange={(o) => {
          if (!o) {
            closePending();
            mfa.reset();
          }
        }}
      >
        <DialogContent>
          <form onSubmit={submitMfa} className="space-y-3">
            <DialogHeader>
              <DialogTitle>Reset MFA?</DialogTitle>
              <DialogDescription>
                This removes the authenticator and recovery codes for{" "}
                <strong>{pending?.user.username}</strong> and signs them out.
                Confirm with your own password and a current code.
              </DialogDescription>
            </DialogHeader>
            <label className="block space-y-1 text-sm">
              Your password
              <Input
                name="password"
                type="password"
                autoComplete="current-password"
                required
              />
            </label>
            <label className="block space-y-1 text-sm">
              Your authenticator code
              <Input name="code" autoComplete="one-time-code" />
            </label>
            {mfa.isError && (
              <p role="alert" className="text-sm text-destructive">
                {describeError(mfa.error).message}
              </p>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={closePending}
                disabled={mfa.isPending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="destructive"
                disabled={mfa.isPending}
              >
                {mfa.isPending ? "Working…" : "Reset MFA"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={issued !== null} onOpenChange={(o) => !o && closeIssued()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{issued?.heading}</DialogTitle>
            <DialogDescription>
              Temporary password for <strong>{issued?.username}</strong>. It is
              shown only once. Hand it over privately; the user must change it
              at first sign-in.
            </DialogDescription>
          </DialogHeader>
          <p
            className="break-all rounded-md border border-border bg-card p-3 font-mono text-sm"
            data-testid="temp-password"
          >
            {issued?.password}
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => void copy()}>
              {copied ? "Copied" : "Copy"}
            </Button>
            <Button onClick={closeIssued}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
