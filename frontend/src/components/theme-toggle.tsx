import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Menu, MenuPopup, MenuRadioGroup, MenuRadioItem, MenuTrigger } from "@/components/ui/menu";
import { useTheme, type ThemePreference } from "@/lib/theme";

const OPTIONS: { value: ThemePreference; label: string; Icon: typeof Sun }[] = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

export function ThemeToggle() {
  const { preference, resolved, setPreference } = useTheme();
  const Current = resolved === "dark" ? Moon : Sun;
  return (
    <Menu>
      <MenuTrigger render={<Button variant="ghost" size="icon" aria-label={`Theme: ${preference}`} />}>
        <Current className="h-4 w-4" />
      </MenuTrigger>
      <MenuPopup align="end">
        <MenuRadioGroup value={preference} onValueChange={(v) => setPreference(v as ThemePreference)}>
          {OPTIONS.map(({ value, label, Icon }) => (
            <MenuRadioItem key={value} value={value}>
              <Icon className="h-4 w-4" />
              {label}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
      </MenuPopup>
    </Menu>
  );
}
