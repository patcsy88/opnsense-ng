import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/features/auth/auth";
import { ThemeProvider } from "@/lib/theme";

export function renderApp(ui: ReactElement, route = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return {
    qc,
    ...render(
      <ThemeProvider>
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={[route]}>
            <AuthProvider>{ui}</AuthProvider>
          </MemoryRouter>
        </QueryClientProvider>
      </ThemeProvider>,
    ),
  };
}

export const ADMIN = { id: "11111111-1111-4111-8111-111111111111", username: "alice", role: "admin" } as const;
export const READER = { id: "22222222-2222-4222-8222-222222222222", username: "bob", role: "read_only" } as const;
export const FW = {
  id: "33333333-3333-4333-8333-333333333333",
  name: "edge-1",
  base_url: "https://192.0.2.1",
  verify_tls: true,
  has_ca_bundle: false,
  allow_writes: false,
  created_at: "2026-11-10T00:00:00Z",
};
