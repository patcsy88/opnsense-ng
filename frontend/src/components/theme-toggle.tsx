import { Dropdown, Label } from "@heroui/react";
import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
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
    <Dropdown>
      <Button variant="ghost" size="icon" aria-label={`Theme: ${preference}`}>
        <Current className="h-4 w-4" />
      </Button>
      <Dropdown.Popover placement="bottom end">
        <Dropdown.Menu
          selectionMode="single"
          disallowEmptySelection
          selectedKeys={new Set([preference])}
          onSelectionChange={(keys) => {
            const v = [...keys][0];
            if (v) setPreference(String(v) as ThemePreference);
          }}
        >
          {OPTIONS.map(({ value, label, Icon }) => (
            <Dropdown.Item key={value} id={value} textValue={label}>
              <Icon className="h-4 w-4" />
              <Label>{label}</Label>
              <Dropdown.ItemIndicator />
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}
