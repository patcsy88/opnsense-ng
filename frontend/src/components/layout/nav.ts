import type { Role } from "@/lib/schemas";
import {
  Activity,
  Flame,
  Globe,
  GitPullRequest,
  LayoutDashboard,
  LayoutList,
  Network,
  Router,
  Shuffle,
  ScrollText,
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
  /** When set, only these roles see the link (the route enforces it too). */
  roles?: Role[];
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, implemented: true },
  { to: "/overview", label: "Overview", icon: LayoutList, implemented: true },
  { to: "/firewall", label: "Firewall", icon: Flame, implemented: true },
  { to: "/nat", label: "NAT", icon: Shuffle, implemented: true },
  { to: "/changes", label: "Changes", icon: GitPullRequest, implemented: true },
  { to: "/network", label: "Network", icon: Network, implemented: true },
  { to: "/logs", label: "Logs", icon: ScrollText, implemented: true, roles: ["admin", "network_admin", "security_admin"] },
  { to: "/traffic", label: "Traffic", icon: Activity, implemented: true, roles: ["admin", "network_admin", "security_admin"] },
  { to: "/dhcp", label: "DHCP", icon: Router, implemented: true, roles: ["admin", "network_admin", "security_admin"] },
  { to: "/dns", label: "DNS", icon: Globe, implemented: true, roles: ["admin", "network_admin", "security_admin"] },
  { to: "/vpn", label: "VPN", icon: ShieldCheck, implemented: true, roles: ["admin", "network_admin", "security_admin"] },
  { to: "/services", label: "Services", icon: Server, implemented: true },
  { to: "/administration", label: "Administration", icon: Settings, implemented: true },
];
