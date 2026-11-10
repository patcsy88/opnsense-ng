import { Navigate, Outlet, useLocation } from "react-router-dom";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/features/auth/auth";
import type { Role } from "@/lib/schemas";

export function ProtectedRoute({ roles }: { roles?: Role[] }) {
  const { user, loading, error, retry } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center text-sm text-muted-foreground" role="status">
        Loading…
      </div>
    );
  }
  if (error) {
    return (
      <div className="mx-auto max-w-md p-6">
        <ErrorState error={error} onRetry={retry} />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (roles && !roles.includes(user.role)) {
    return (
      <div role="alert" className="p-6">
        <h1 className="text-xl font-semibold">Not permitted</h1>
        <p className="text-sm text-muted-foreground">Your role does not allow access to this page.</p>
      </div>
    );
  }
  return <Outlet />;
}
