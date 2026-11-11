import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { NAV_ITEMS } from "@/components/layout/nav";
import { ProtectedRoute } from "@/components/protected-route";
import { AdministrationPage } from "@/pages/administration";
import { ChangeDetailPage } from "@/pages/change-detail";
import { ChangesPage } from "@/pages/changes";
import { DashboardPage } from "@/pages/dashboard";
import { FirewallConnectionsPage } from "@/pages/firewall-connections";
import { LogsPage } from "@/pages/logs";
import { LoginPage } from "@/pages/login";
import { FirewallPage } from "@/pages/firewall";
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
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="/changes" element={<ChangesPage />} />
          <Route path="/changes/:id" element={<ChangeDetailPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route element={<ProtectedRoute roles={["admin", "network_admin", "security_admin"]} />}>
            <Route path="/logs" element={<LogsPage />} />
          </Route>
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
