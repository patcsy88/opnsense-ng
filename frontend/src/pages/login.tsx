import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/features/auth/auth";
import { api, ApiError } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { loginFormSchema } from "@/lib/schemas";

export function LoginPage() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (user) return <Navigate to={from} replace />;

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    const formEl = e.currentTarget;
    const form = new FormData(formEl);
    const parsed = loginFormSchema.safeParse({
      username: form.get("username"),
      password: form.get("password"),
    });
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Invalid input");
      return;
    }
    setPending(true);
    try {
      const res = await api.login(parsed.data.username, parsed.data.password);
      setUser(res.user);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError && err.kind === "unauthorized" ? err.message : describeError(err).message);
      const pw = formEl.elements.namedItem("password");
      if (pw instanceof HTMLInputElement) pw.value = "";
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="grid min-h-screen place-items-center p-4">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-xl">Sign in</CardTitle>
          <CardDescription>OPNsense Firewall Manager</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => void onSubmit(e)} className="space-y-4" noValidate>
            <div className="space-y-1">
              <Label htmlFor="username">Username</Label>
              <Input id="username" name="username" autoComplete="username" autoCapitalize="none" required />
            </div>
            <div className="space-y-1">
              <Label htmlFor="password">Password</Label>
              <Input id="password" name="password" type="password" autoComplete="current-password" required />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={pending}>
              {pending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
