import { LogOut, LogOutIcon, Menu, UserRound } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { useAuth } from "@/features/auth/auth";
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
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm hover:bg-muted",
              isActive && "bg-muted font-medium text-primary",
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
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label="User menu">
          <UserRound className="h-4 w-4" />
          <span className="hidden sm:inline">{user.username}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuLabel>
          {user.username} · {user.role}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void end(api.logout)}>
          <LogOut className="h-4 w-4" /> Sign out
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void end(api.logoutAll)}>
          <LogOutIcon className="h-4 w-4" /> Sign out everywhere
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppLayout() {
  const [open, setOpen] = useState(false);
  return (
    <div className="min-h-screen md:flex">
      <aside className="hidden w-60 shrink-0 border-r border-border bg-card p-4 md:block">
        <div className="mb-6 px-3 text-sm font-semibold">OPNsense Manager</div>
        <NavLinks />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center gap-2 border-b border-border bg-card px-4">
          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open navigation">
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent>
              <SheetTitle className="mb-4 px-3 text-sm font-semibold">OPNsense Manager</SheetTitle>
              <SheetDescription className="sr-only">Site navigation</SheetDescription>
              <SheetClose asChild>
                <span>
                  <NavLinks onNavigate={() => setOpen(false)} />
                </span>
              </SheetClose>
            </SheetContent>
          </Sheet>
          <div className="flex-1 text-sm font-semibold md:hidden">OPNsense Manager</div>
          <div className="ml-auto flex items-center gap-1">
            <ThemeToggle />
            <UserMenu />
          </div>
        </header>
        <main className="flex-1 p-4 pb-20 md:p-6 md:pb-6">
          <Outlet />
        </main>
        <nav
          aria-label="Quick"
          className="fixed inset-x-0 bottom-0 z-40 grid grid-cols-4 border-t border-border bg-card md:hidden"
        >
          {["/", "/firewall", "/changes", "/services"].map((path) => NAV_ITEMS.find((n) => n.to === path)).map((item) =>
            item ? (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn("flex flex-col items-center gap-0.5 py-2 text-[11px]", isActive ? "text-primary" : "text-muted-foreground")
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
  );
}
