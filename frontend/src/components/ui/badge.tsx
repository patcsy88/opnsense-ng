import { Chip } from "@heroui/react";
import type * as React from "react";

// Our variant names stay (ADR-0025); HeroUI's Chip is used inside.
const VARIANTS = {
  default: { color: "default", variant: "primary" },
  destructive: { color: "danger", variant: "primary" },
  error: { color: "danger", variant: "soft" },
  info: { color: "accent", variant: "soft" },
  outline: { color: "default", variant: "secondary" },
  secondary: { color: "default", variant: "soft" },
  success: { color: "success", variant: "soft" },
  warning: { color: "warning", variant: "soft" },
} as const;

type ChipProps = React.ComponentProps<typeof Chip>;

export interface BadgeProps
  extends Omit<ChipProps, "color" | "variant" | "size">,
    Omit<React.HTMLAttributes<HTMLSpanElement>, keyof ChipProps> {
  variant?: keyof typeof VARIANTS;
  size?: "default" | "sm" | "lg";
}

const SIZES = { default: "md", sm: "sm", lg: "lg" } as const;

export function Badge({ variant = "secondary", size = "default", ...props }: BadgeProps): React.ReactElement {
  return <Chip {...VARIANTS[variant]} size={SIZES[size]} {...props} />;
}
