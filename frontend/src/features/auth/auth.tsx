import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { api, ApiError, setUnauthorizedHandler } from "@/lib/api";
import type { Role, User } from "@/lib/schemas";

export const ME_KEY = ["auth", "me"] as const;

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  error: unknown;
  retry: () => void;
  setUser: (u: User) => void;
  /** Drops the user and every cached query (firewall data must not outlive the session). */
  clearSession: () => void;
  hasRole: (...roles: Role[]) => boolean;
}
const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ME_KEY,
    queryFn: async (): Promise<User | null> => {
      try {
        return await api.me();
      } catch (e) {
        if (e instanceof ApiError && e.kind === "unauthorized") return null;
        throw e;
      }
    },
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });

  const clearSession = useCallback(() => {
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== ME_KEY[0] });
    qc.getMutationCache().clear();
    qc.setQueryData(ME_KEY, null);
  }, [qc]);

  useEffect(() => {
    setUnauthorizedHandler(clearSession);
    return () => setUnauthorizedHandler(null);
  }, [clearSession]);

  const user = query.data ?? null;
  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading: query.isPending,
      error: query.isError ? query.error : null,
      retry: () => void query.refetch(),
      setUser: (u) => qc.setQueryData(ME_KEY, u),
      clearSession,
      // UI convenience only: the backend enforces RBAC.
      hasRole: (...roles) => user !== null && roles.includes(user.role),
    }),
    [user, query, qc, clearSession],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
