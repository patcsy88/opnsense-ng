import { Drawer, Dropdown, Label, Separator } from "@heroui/react";
import { LogOut, LogOutIcon, Menu as MenuIcon, UserRound } from "lucide-react";
import { Suspense, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { useAuth } from "@/features/auth/auth";
import { FirewallPicker, SelectedFirewallProvider } from "@/features/firewall/selected-firewall";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { NAV_ITEMS } from "./nav";

function NavLinks({ onNavigate, className }: { onNavigate?: () => void; className?: string }) {
  const { user } = useAuth();
  const items = NAV_ITEMS.filter((n) => !n.roles || (user !== null && n.roles.includes(user.role)));
  return (
    <nav aria-label="Main" className={cn("flex flex-col gap-1", className)}>
      {items.map(({ to, label, icon: Icon, implemented }) => (
        <NavLink
          key={to}
          to={to}
          end={to === "/"}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
              isActive && "bg-sidebar-accent font-medium text-sidebar-accent-foreground",
            )
          }
        >
          <Icon className="h-4 w-4" aria-hidden />
          {label}
          {!implemented && <span className="ml-auto text-[10px] uppercase text-muted-foreground">Planned</span>}
        </NavLink>
      ))}
    </nav>
  );
}

function UserMenu() {
  const { user, clearSession } = useAuth();
  const navigate = useNavigate();
  const end = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch {
      /* the session may already be gone; clear locally regardless */
    }
    clearSession();
    navigate("/login", { replace: true });
  };
  if (!user) return null;
  return (
    <Dropdown>
      <Button variant="ghost" size="sm" aria-label="User menu">
        <UserRound className="h-4 w-4" />
        <span className="hidden sm:inline">{user.username}</span>
      </Button>
      <Dropdown.Popover placement="bottom end">
        <div className="px-3 py-2 text-xs text-muted-foreground">
          {user.username} · {user.role}
        </div>
        <Separator />
        <Dropdown.Menu
          onAction={(key) => {
            if (key === "account") navigate("/account");
            else if (key === "logout") void end(api.logout);
            else if (key === "logout-all") void end(api.logoutAll);
          }}
        >
          <Dropdown.Item id="account" textValue="Account and MFA">
            <UserRound className="h-4 w-4" /> <Label>Account and MFA</Label>
          </Dropdown.Item>
          <Dropdown.Item id="logout" textValue="Sign out">
            <LogOut className="h-4 w-4" /> <Label>Sign out</Label>
          </Dropdown.Item>
          <Dropdown.Item id="logout-all" textValue="Sign out everywhere">
            <LogOutIcon className="h-4 w-4" /> <Label>Sign out everywhere</Label>
          </Dropdown.Item>
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}

/** Pages with no single-firewall scope keep the picker out of the bar. */
function showsPicker(path: string): boolean {
  if (path === "/" || path === "/account") return false;
  if (path.startsWith("/administration")) return path.startsWith("/administration/changes");
  return true;
}

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  return (
    <SelectedFirewallProvider>
    <div className="min-h-screen md:flex">
      <aside className="hidden w-60 shrink-0 border-r border-sidebar-border bg-sidebar p-4 md:block">
        <div className="mb-6 px-3 font-heading text-sm font-semibold tracking-tight">OPNsense Manager</div>
        <NavLinks />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center gap-2 border-b border-border bg-background pl-[max(1rem,env(safe-area-inset-left))] pr-[max(1rem,env(safe-area-inset-right))]">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            aria-label="Open navigation"
            onClick={() => setOpen(true)}
          >
            <MenuIcon className="h-5 w-5" />
          </Button>
          <Drawer.Backdrop isOpen={open} onOpenChange={setOpen}>
            <Drawer.Content placement="left">
              <Drawer.Dialog aria-label="Site navigation">
                <Drawer.Header>
                  <Drawer.Heading className="px-3 text-sm font-semibold">OPNsense Manager</Drawer.Heading>
                </Drawer.Header>
                <Drawer.Body>
                  <NavLinks onNavigate={() => setOpen(false)} className="px-2" />
                </Drawer.Body>
              </Drawer.Dialog>
            </Drawer.Content>
          </Drawer.Backdrop>
          <div className="flex-1 text-sm font-semibold md:hidden">OPNsense Manager</div>
          <div className="ml-auto flex items-center gap-1">
            {showsPicker(pathname) && <FirewallPicker />}
            <ThemeToggle />
            <UserMenu />
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 p-4 pb-[calc(5rem+env(safe-area-inset-bottom))] md:p-6 md:pb-6">
          <Suspense fallback={<Loading />}>
            <Outlet />
          </Suspense>
        </main>
        <nav
          aria-label="Quick"
          className="fixed inset-x-0 bottom-0 z-40 grid grid-cols-4 border-t border-sidebar-border bg-sidebar pb-[env(safe-area-inset-bottom)] pl-[env(safe-area-inset-left)] pr-[env(safe-area-inset-right)] md:hidden"
        >
          {["/", "/firewall", "/services", "/administration"].map((path) => NAV_ITEMS.find((n) => n.to === path)).map((item) =>
            item ? (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn("flex flex-col items-center gap-0.5 py-2 text-[11px]", isActive ? "text-foreground" : "text-muted-foreground")
                }
              >
                <item.icon className="h-5 w-5" aria-hidden />
                {item.label}
              </NavLink>
            ) : null,
          )}
        </nav>
      </div>
    </div>
    </SelectedFirewallProvider>
  );
}
