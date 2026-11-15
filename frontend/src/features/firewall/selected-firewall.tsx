import { SelectField } from "@/components/ui/select-field";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "@/lib/api";
import type { FirewallOption } from "@/lib/schemas";

const STORAGE_KEY = "selected-firewall";

interface Value {
  options: UseQueryResult<FirewallOption[]>;
  firewalls: FirewallOption[];
  /** The chosen firewall id, or the first one until a choice is made. Null with no firewalls. */
  selected: string | null;
  select: (id: string) => void;
}

const Ctx = createContext<Value | null>(null);

function stored(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

/** Holds the one firewall choice shared by every page. Only the id is kept, per browser tab. */
export function SelectedFirewallProvider({
  children,
}: {
  children: ReactNode;
}) {
  const options = useQuery({
    queryKey: ["firewalls", "options"],
    queryFn: api.listFirewallOptions,
  });
  const [chosen, setChosen] = useState<string | null>(stored);
  const firewalls = useMemo(() => options.data ?? [], [options.data]);
  const selected =
    firewalls.find((f) => f.id === chosen)?.id ?? firewalls[0]?.id ?? null;

  const select = useCallback((id: string) => {
    setChosen(id);
    try {
      sessionStorage.setItem(STORAGE_KEY, id);
    } catch {
      /* storage may be unavailable; the choice then lasts until reload */
    }
  }, []);

  const value = useMemo(
    () => ({ options, firewalls, selected, select }),
    [options, firewalls, selected, select],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSelectedFirewall(): Value {
  const v = useContext(Ctx);
  if (v === null)
    throw new Error("useSelectedFirewall needs SelectedFirewallProvider");
  return v;
}

export function FirewallPicker() {
  const { firewalls, selected, select } = useSelectedFirewall();
  if (firewalls.length === 0) return null;
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="hidden sm:inline">Firewall</span>
      <SelectField
        aria-label="Firewall"
        className="max-w-[10rem] sm:max-w-[14rem]"
        value={selected ?? ""}
        onValueChange={select}
        options={firewalls.map((f) => ({ value: f.id, label: f.name }))}
      />
    </label>
  );
}
