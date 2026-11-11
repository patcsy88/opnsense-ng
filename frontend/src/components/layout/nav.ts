import {
  Activity,
  Flame,
  LayoutDashboard,
  Network,
  Server,
  Settings,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** true = page exists; false renders the Planned placeholder. */
  implemented: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, implemented: true },
  { to: "/firewall", label: "Firewall", icon: Flame, implemented: false },
  { to: "/network", label: "Network", icon: Network, implemented: true },
  { to: "/vpn", label: "VPN", icon: ShieldCheck, implemented: false },
  { to: "/monitoring", label: "Monitoring", icon: Activity, implemented: false },
  { to: "/services", label: "Services", icon: Server, implemented: false },
  { to: "/administration", label: "Administration", icon: Settings, implemented: true },
];
