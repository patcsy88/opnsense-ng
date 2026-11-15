import { lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { NAV_ITEMS } from "@/components/layout/nav";
import { ProtectedRoute } from "@/components/protected-route";
import { DashboardPage } from "@/pages/dashboard";
import { LoginPage } from "@/pages/login";

const AdministrationPage = lazy(() => import("@/pages/administration").then((m) => ({ default: m.AdministrationPage })));
const AccountPage = lazy(() => import("@/pages/account").then((m) => ({ default: m.AccountPage })));
const AuditPage = lazy(() => import("@/pages/audit").then((m) => ({ default: m.AuditPage })));
const UsersPage = lazy(() => import("@/pages/users").then((m) => ({ default: m.UsersPage })));
const ChangeDetailPage = lazy(() => import("@/pages/change-detail").then((m) => ({ default: m.ChangeDetailPage })));
const ChangesPage = lazy(() => import("@/pages/changes").then((m) => ({ default: m.ChangesPage })));
const FirewallConnectionsPage = lazy(() => import("@/pages/firewall-connections").then((m) => ({ default: m.FirewallConnectionsPage })));
const NatPage = lazy(() => import("@/pages/nat").then((m) => ({ default: m.NatPage })));
const OverviewPage = lazy(() => import("@/pages/overview").then((m) => ({ default: m.OverviewPage })));
const DhcpPage = lazy(() => import("@/pages/dhcp").then((m) => ({ default: m.DhcpPage })));
const DnsPage = lazy(() => import("@/pages/dns").then((m) => ({ default: m.DnsPage })));
const LogsPage = lazy(() => import("@/pages/logs").then((m) => ({ default: m.LogsPage })));
const ServicesPage = lazy(() => import("@/pages/services").then((m) => ({ default: m.ServicesPage })));
const TrafficPage = lazy(() => import("@/pages/traffic").then((m) => ({ default: m.TrafficPage })));
const VpnPage = lazy(() => import("@/pages/vpn").then((m) => ({ default: m.VpnPage })));
const FirewallPage = lazy(() => import("@/pages/firewall").then((m) => ({ default: m.FirewallPage })));
const NetworkPage = lazy(() => import("@/pages/network").then((m) => ({ default: m.NetworkPage })));
const PlannedPage = lazy(() => import("@/pages/planned").then((m) => ({ default: m.PlannedPage })));

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
          <Route path="/administration/changes" element={<ChangesPage />} />
          <Route path="/administration/changes/:id" element={<ChangeDetailPage />} />
          <Route path="/nat" element={<NatPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route element={<ProtectedRoute roles={["admin", "network_admin", "security_admin"]} />}>
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/traffic" element={<TrafficPage />} />
            <Route path="/dhcp" element={<DhcpPage />} />
            <Route path="/dns" element={<DnsPage />} />
          </Route>
          <Route path="/dhcp/entries" element={<Navigate to="/dhcp" replace />} />
          <Route element={<ProtectedRoute roles={["admin", "network_admin", "security_admin"]} />}>
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
          <Route path="/changes/*" element={<Navigate to="/administration/changes" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
