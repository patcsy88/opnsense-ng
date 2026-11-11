import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { NAV_ITEMS } from "@/components/layout/nav";
import { ProtectedRoute } from "@/components/protected-route";
import { AdministrationPage } from "@/pages/administration";
import { DashboardPage } from "@/pages/dashboard";
import { FirewallConnectionsPage } from "@/pages/firewall-connections";
import { LoginPage } from "@/pages/login";
import { NetworkPage } from "@/pages/network";
import { PlannedPage } from "@/pages/planned";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<DashboardPage />} />
          {NAV_ITEMS.filter((n) => !n.implemented).map((n) => (
            <Route key={n.to} path={n.to} element={<PlannedPage title={n.label} />} />
          ))}
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/administration" element={<AdministrationPage />} />
          <Route element={<ProtectedRoute roles={["admin"]} />}>
            <Route path="/administration/firewalls" element={<FirewallConnectionsPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
