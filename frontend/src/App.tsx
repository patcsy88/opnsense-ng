import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { NAV_ITEMS } from "@/components/layout/nav";
import { ProtectedRoute } from "@/components/protected-route";
import { AdministrationPage } from "@/pages/administration";
import { AccountPage } from "@/pages/account";
import { AuditPage } from "@/pages/audit";
import { UsersPage } from "@/pages/users";
import { ChangeDetailPage } from "@/pages/change-detail";
import { ChangesPage } from "@/pages/changes";
import { DashboardPage } from "@/pages/dashboard";
import { FirewallConnectionsPage } from "@/pages/firewall-connections";
import { NatPage } from "@/pages/nat";
import { OverviewPage } from "@/pages/overview";
import { DhcpPage } from "@/pages/dhcp";
import { DnsPage } from "@/pages/dns";
import { LogsPage } from "@/pages/logs";
import { ServicesPage } from "@/pages/services";
import { TrafficPage } from "@/pages/traffic";
import { VpnPage } from "@/pages/vpn";
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
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="/changes" element={<ChangesPage />} />
          <Route path="/changes/:id" element={<ChangeDetailPage />} />
          <Route path="/nat" element={<NatPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route element={<ProtectedRoute roles={["admin", "network_admin", "security_admin"]} />}>
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/traffic" element={<TrafficPage />} />
            <Route path="/dhcp" element={<DhcpPage />} />
            <Route path="/dns" element={<DnsPage />} />
            <Route path="/vpn" element={<VpnPage />} />
          </Route>
          <Route path="/account" element={<AccountPage />} />
          <Route path="/services" element={<ServicesPage />} />
          <Route path="/administration" element={<AdministrationPage />} />
          <Route element={<ProtectedRoute roles={["admin", "security_admin"]} />}>
            <Route path="/administration/audit" element={<AuditPage />} />
          </Route>
          <Route element={<ProtectedRoute roles={["admin"]} />}>
            <Route path="/administration/firewalls" element={<FirewallConnectionsPage />} />
            <Route path="/administration/users" element={<UsersPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
