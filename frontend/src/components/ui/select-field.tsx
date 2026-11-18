import { ListBox, Select } from "@heroui/react";
import type { ReactElement } from "react";

export interface SelectOption {
  value: string;
  label: string;
}

interface SelectFieldProps {
  options: readonly SelectOption[];
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  /** Submitted with the surrounding form, so FormData reads keep working. */
  name?: string;
  id?: string;
  disabled?: boolean;
  className?: string;
  size?: "sm" | "default" | "lg";
  "aria-label"?: string;
}

/** Native-select-shaped wrapper over the HeroUI Select, used wherever a plain choice list is needed. */
export function SelectField({
  options,
  value,
  defaultValue,
  onValueChange,
  name,
  id,
  disabled,
  className,
  "aria-label": ariaLabel,
}: SelectFieldProps): ReactElement {
  return (
    <Select
      fullWidth
      id={id}
      name={name}
      aria-label={ariaLabel}
      className={className}
      isDisabled={disabled}
      selectedKey={value}
      defaultSelectedKey={defaultValue}
      onSelectionChange={onValueChange ? (k) => k !== null && onValueChange(String(k)) : undefined}
    >
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox items={options.map((o) => ({ ...o, id: o.value }))}>
          {(o) => (
            <ListBox.Item id={o.id} textValue={o.label}>
              {o.label}
            </ListBox.Item>
          )}
        </ListBox>
      </Select.Popover>
    </Select>
  );
}
