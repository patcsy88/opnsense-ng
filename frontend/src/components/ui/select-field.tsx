import { Select, SelectItem, SelectPopup, SelectTrigger, SelectValue } from "@/components/ui/select";

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

/** Native-select-shaped wrapper over the coss Select, used wherever a plain choice list is needed. */
export function SelectField({
  options,
  value,
  defaultValue,
  onValueChange,
  name,
  id,
  disabled,
  className,
  size,
  "aria-label": ariaLabel,
}: SelectFieldProps) {
  return (
    <Select
      items={options}
      value={value}
      defaultValue={defaultValue}
      onValueChange={onValueChange ? (v) => onValueChange(String(v)) : undefined}
      name={name}
      disabled={disabled}
    >
      <SelectTrigger id={id} aria-label={ariaLabel} className={className} size={size}>
        <SelectValue />
      </SelectTrigger>
      <SelectPopup>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectPopup>
    </Select>
  );
}
