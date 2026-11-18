import { Tabs as HeroTabs } from "@heroui/react";
import type { ComponentProps, ReactElement, ReactNode } from "react";

// Tabs are used as a section switcher: the page renders its own content from `value` (ADR-0025).
export function Tabs({
  value,
  onValueChange,
  children,
  className,
}: {
  value: string;
  onValueChange: (value: string) => void;
  children: ReactNode;
  className?: string;
}): ReactElement {
  return (
    <HeroTabs selectedKey={value} onSelectionChange={(k) => onValueChange(String(k))} className={className}>
      {children}
    </HeroTabs>
  );
}

export function TabsList({ children, ...props }: ComponentProps<typeof HeroTabs.List>): ReactElement {
  return (
    <HeroTabs.ListContainer>
      <HeroTabs.List {...props}>{children}</HeroTabs.List>
    </HeroTabs.ListContainer>
  );
}

export function TabsTab({
  value,
  children,
  onClick,
  ...props
}: Omit<ComponentProps<typeof HeroTabs.Tab>, "id" | "children"> & { value: string; children: ReactNode }): ReactElement {
  return (
    <HeroTabs.Tab id={value} onClick={onClick} {...props}>
      {children}
      <HeroTabs.Indicator />
    </HeroTabs.Tab>
  );
}
