import { Tabs, TabsList, TabsTab } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/** "absent" means not in the firewall's service list, which is the case for a disabled service. */
export type EngineState = "running" | "stopped" | "absent" | "unknown";

export interface Engines {
  dnsmasq: EngineState;
  unbound: EngineState;
  kea: EngineState;
  loading: boolean;
}

function state(
  list: { id: string; running: boolean }[] | undefined,
  ...ids: string[]
): EngineState {
  if (!list) return "unknown";
  const found = list.filter((s) => ids.includes(s.id));
  if (found.length === 0) return "absent";
  return found.some((s) => s.running) ? "running" : "stopped";
}

/** Which DHCP and DNS engines the firewall has, and whether they run, from its service list. */
export function useEngines(firewallId: string | null): Engines {
  const q = useQuery({
    queryKey: ["firewalls", firewallId, "services"],
    queryFn: () => api.services(firewallId as string),
    enabled: firewallId !== null,
    refetchInterval: 60_000,
  });
  const list = q.data?.services;
  return {
    dnsmasq: state(list, "dnsmasq"),
    unbound: state(list, "unbound"),
    kea: state(list, "kea-dhcp/v4", "kea-dhcp4"),
    loading: q.isPending && firewallId !== null,
  };
}

export const engineLabel: Record<EngineState, string> = {
  running: "running",
  stopped: "stopped",
  absent: "not running",
  unknown: "status unknown",
};

/** Shown above an engine's tools when the engine is not serving, so edits are not mistaken for live. */
export function InactiveNotice({
  name,
  state: st,
}: {
  name: string;
  state: EngineState;
}) {
  if (st === "running" || st === "unknown") return null;
  const why = st === "absent" ? " (disabled, or not installed)" : "";
  return (
    <p
      role="status"
      className="rounded-md border border-border bg-muted p-2 text-sm"
    >
      {name} is {engineLabel[st]}
      {why} on this firewall, so changes here will not affect clients until it
      is started.
    </p>
  );
}

export interface EngineTab<T extends string> {
  id: T;
  name: string;
  state: EngineState;
}

/** One tab per engine. The status line says which engines run, so the user knows who serves clients. */
export function EngineTabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
}: {
  label: string;
  tabs: EngineTab<T>[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="space-y-1">
      <Tabs value={value} onValueChange={(v) => onChange(v as T)}>
        <TabsList aria-label={label}>
          {tabs.map((t) => (
            <TabsTab key={t.id} value={t.id}>
              {t.name}
            </TabsTab>
          ))}
        </TabsList>
      </Tabs>
      <p className="text-xs text-muted-foreground">
        {tabs.map((t) => `${t.name}: ${engineLabel[t.state]}`).join(" · ")}
      </p>
    </div>
  );
}

/** The engine to open first: the first running one, else the first listed. */
export function firstRunning<T extends string>(tabs: EngineTab<T>[]): T {
  return (tabs.find((t) => t.state === "running") ?? tabs[0]!).id;
}
