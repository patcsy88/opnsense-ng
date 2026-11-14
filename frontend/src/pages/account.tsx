import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ME_KEY, useAuth } from "@/features/auth/auth";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";

const QUIET_ZONE = 4;

/** Draws the QR matrix from the backend as inline SVG: no image, data: URL or injected markup. */
export function QrCode({ matrix }: { matrix: boolean[][] }) {
  const size = matrix.length + QUIET_ZONE * 2;
  const cells: ReactNode[] = [];
  matrix.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark)
        cells.push(
          <rect
            key={`${x}-${y}`}
            x={x + QUIET_ZONE}
            y={y + QUIET_ZONE}
            width={1}
            height={1}
          />,
        );
    }),
  );
  return (
    <svg
      role="img"
      aria-label="QR code for your authenticator app"
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className="h-56 w-56 rounded-md border border-border"
    >
      <rect width={size} height={size} fill="#fff" />
      <g fill="#000">{cells}</g>
    </svg>
  );
}

function RecoveryCodes({
  codes,
  onDone,
}: {
  codes: string[];
  onDone: () => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Save your recovery codes</CardTitle>
        <CardDescription>
          Each code works once and lets you sign in without your authenticator
          app. They are shown only now. Store them somewhere safe, apart from
          this device.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul
          className="grid grid-cols-2 gap-2 font-mono text-sm"
          aria-label="Recovery codes"
        >
          {codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <Button onClick={onDone}>I have saved these codes</Button>
      </CardContent>
    </Card>
  );
}

function Enrol({ onCodes }: { onCodes: (codes: string[]) => void }) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: (password: string) => api.mfaEnrolStart(password),
    onError: (e) => setError(describeError(e).message),
  });
  const confirm = useMutation({
    mutationFn: (code: string) => api.mfaEnrolConfirm(code),
    onSuccess: async (res) => {
      onCodes(res.recovery_codes);
      await qc.invalidateQueries({ queryKey: ME_KEY });
      await qc.invalidateQueries({ queryKey: ["mfa"] });
    },
    onError: (e) => setError(describeError(e).message),
  });

  const submitPassword = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    const password = String(
      new FormData(e.currentTarget).get("password") ?? "",
    );
    if (password) start.mutate(password);
  };
  const submitCode = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    const code = String(new FormData(e.currentTarget).get("code") ?? "").trim();
    if (code) confirm.mutate(code);
  };

  const begun = start.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Set up two-factor authentication</CardTitle>
        <CardDescription>
          Use an authenticator app such as Aegis, 2FAS, Google Authenticator or
          1Password.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!begun ? (
          <form
            onSubmit={submitPassword}
            className="max-w-sm space-y-3"
            noValidate
          >
            <div className="space-y-1">
              <Label htmlFor="enrol-password">Confirm your password</Label>
              <Input
                id="enrol-password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
              />
            </div>
            <Button type="submit" disabled={start.isPending}>
              Continue
            </Button>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-start gap-6">
              <QrCode matrix={begun.qr} />
              <div className="space-y-2 text-sm">
                <p>Scan the QR code, or type this key into your app:</p>
                <p
                  className="break-all font-mono text-base"
                  aria-label="Setup key"
                >
                  {begun.secret}
                </p>
                <p className="text-xs text-muted-foreground">
                  Keep this key private. It is not shown again.
                </p>
              </div>
            </div>
            <form
              onSubmit={submitCode}
              className="max-w-sm space-y-3"
              noValidate
            >
              <div className="space-y-1">
                <Label htmlFor="enrol-code">Code from your app</Label>
                <Input
                  id="enrol-code"
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
              </div>
              <Button type="submit" disabled={confirm.isPending}>
                Turn on two-factor authentication
              </Button>
            </form>
          </div>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function Manage({
  required,
  left,
  onCodes,
}: {
  required: boolean;
  left: number;
  onCodes: (codes: string[]) => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: ME_KEY });
    await qc.invalidateQueries({ queryKey: ["mfa"] });
  };
  const regenerate = useMutation({
    mutationFn: (v: { password: string; code: string }) =>
      api.mfaRegenerateCodes(v.password, v.code),
    onSuccess: async (res) => {
      onCodes(res.recovery_codes);
      await refresh();
    },
    onError: (e) => setError(describeError(e).message),
  });
  const disable = useMutation({
    mutationFn: (v: { password: string; code: string }) =>
      api.mfaDisable(v.password, v.code),
    onSuccess: async () => {
      await refresh();
    },
    onError: (e) => setError(describeError(e).message),
  });

  const read = (form: HTMLFormElement) => {
    const data = new FormData(form);
    return {
      password: String(data.get("password") ?? ""),
      code: String(data.get("code") ?? "").trim(),
    };
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Two-factor authentication <Badge variant="success">On</Badge>
        </CardTitle>
        <CardDescription>
          {left} recovery code{left === 1 ? "" : "s"} left.{" "}
          {required
            ? "Your role requires it, so it cannot be turned off."
            : "You can turn it off below."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="max-w-sm space-y-3"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            const v = read(e.currentTarget);
            if (v.password && v.code) regenerate.mutate(v);
          }}
        >
          <div className="space-y-1">
            <Label htmlFor="mfa-password">Password</Label>
            <Input
              id="mfa-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="mfa-code">
              Code from your app, or a recovery code
            </Label>
            <Input
              id="mfa-code"
              name="code"
              autoComplete="one-time-code"
              required
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              variant="outline"
              disabled={regenerate.isPending}
            >
              Get new recovery codes
            </Button>
            {!required && (
              <Button
                type="button"
                variant="destructive"
                disabled={disable.isPending}
                onClick={(e) => {
                  const form = e.currentTarget.form;
                  if (!form) return;
                  setError(null);
                  const v = read(form);
                  if (v.password && v.code) disable.mutate(v);
                }}
              >
                Turn off
              </Button>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            New recovery codes replace the old ones and sign you out of your
            other sessions.
          </p>
        </form>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function ChangePassword({ mfaEnabled, forced }: { mfaEnabled: boolean; forced: boolean }) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const change = useMutation({
    mutationFn: (v: { current: string; next: string; code?: string }) => api.changePassword(v.current, v.next, v.code),
    onSuccess: async () => {
      setDone(true);
      await qc.invalidateQueries({ queryKey: ME_KEY });
      await qc.invalidateQueries({ queryKey: ["mfa"] });
    },
    onError: (e) => setError(describeError(e).message),
  });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setDone(false);
    const form = e.currentTarget;
    const data = new FormData(form);
    const current = String(data.get("current") ?? "");
    const next = String(data.get("next") ?? "");
    const again = String(data.get("again") ?? "");
    const code = String(data.get("code") ?? "").trim();
    if (!current || !next) return;
    if (next !== again) {
      setError("The new passwords do not match");
      return;
    }
    change.mutate({ current, next, code: code || undefined }, { onSuccess: () => form.reset() });
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>
          {forced
            ? "You are using a temporary password. Choose your own to continue."
            : "At least 12 characters. Your other sessions will be signed out."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="max-w-sm space-y-3" noValidate>
          <div className="space-y-1">
            <Label htmlFor="pw-current">{forced ? "Temporary password" : "Current password"}</Label>
            <Input id="pw-current" name="current" type="password" autoComplete="current-password" required />
          </div>
          <div className="space-y-1">
            <Label htmlFor="pw-next">New password</Label>
            <Input id="pw-next" name="next" type="password" autoComplete="new-password" required />
          </div>
          <div className="space-y-1">
            <Label htmlFor="pw-again">Repeat new password</Label>
            <Input id="pw-again" name="again" type="password" autoComplete="new-password" required />
          </div>
          {mfaEnabled && (
            <div className="space-y-1">
              <Label htmlFor="pw-code">Code from your app</Label>
              <Input id="pw-code" name="code" autoComplete="one-time-code" required />
            </div>
          )}
          <Button type="submit" disabled={change.isPending}>
            Change password
          </Button>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          {done && (
            <p role="status" className="text-sm">
              Password changed.
            </p>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

export function AccountPage() {
  const { user } = useAuth();
  const [codes, setCodes] = useState<string[] | null>(null);
  const status = useQuery({
    queryKey: ["mfa", "status"],
    queryFn: () => api.mfaStatus(),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Account</h1>
      {user?.mfa_enrolment_required && (
        <p
          role="alert"
          className="rounded-md border border-border bg-card p-3 text-sm"
        >
          Your role requires two-factor authentication. Set it up to continue
          using the app.
        </p>
      )}
      {user?.must_change_password && (
        <p role="alert" className="rounded-md border border-border bg-card p-3 text-sm">
          Your password was set by an administrator. Change it to continue using the app.
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>{user?.username}</CardTitle>
          <CardDescription>Role: {user?.role}</CardDescription>
        </CardHeader>
      </Card>
      {user && <ChangePassword mfaEnabled={user.mfa_enabled} forced={user.must_change_password} />}
      {codes ? (
        <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />
      ) : status.isError ? (
        <ErrorState
          error={status.error}
          onRetry={() => void status.refetch()}
        />
      ) : status.data ? (
        status.data.enabled ? (
          <Manage
            required={status.data.required}
            left={status.data.recovery_codes_left}
            onCodes={setCodes}
          />
        ) : (
          <Enrol onCodes={setCodes} />
        )
      ) : (
        <p role="status" className="text-sm text-muted-foreground">
          Loading…
        </p>
      )}
    </div>
  );
}
