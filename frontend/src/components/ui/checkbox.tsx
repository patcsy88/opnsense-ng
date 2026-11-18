import { Checkbox as HeroCheckbox } from "@heroui/react";
import type { ReactElement, ReactNode } from "react";

// Keeps native-checkbox naming so forms that read FormData (name, value) keep working (ADR-0025).
export interface CheckboxProps {
  name?: string;
  value?: string;
  checked?: boolean;
  defaultChecked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
  children: ReactNode;
}

export function Checkbox({
  checked,
  defaultChecked,
  onCheckedChange,
  disabled,
  children,
  ...props
}: CheckboxProps): ReactElement {
  return (
    <HeroCheckbox
      {...props}
      isSelected={checked}
      defaultSelected={defaultChecked}
      onChange={onCheckedChange}
      isDisabled={disabled}
    >
      <HeroCheckbox.Control>
        <HeroCheckbox.Indicator />
      </HeroCheckbox.Control>
      <HeroCheckbox.Content>{children}</HeroCheckbox.Content>
    </HeroCheckbox>
  );
}
