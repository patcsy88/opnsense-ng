import { Button as HeroButton } from "@heroui/react";
import type * as React from "react";
import { Spinner } from "@/components/ui/spinner";

// Our variant and size names stay as they were (ADR-0025); HeroUI's names are used inside.
type HeroProps = React.ComponentProps<typeof HeroButton>;

const VARIANTS = {
  default: "primary",
  destructive: "danger",
  "destructive-outline": "danger-soft",
  ghost: "ghost",
  link: "ghost",
  outline: "outline",
  secondary: "secondary",
} as const satisfies Record<string, NonNullable<HeroProps["variant"]>>;

const SIZES = {
  default: { size: "md", isIconOnly: false },
  sm: { size: "sm", isIconOnly: false },
  lg: { size: "lg", isIconOnly: false },
  icon: { size: "md", isIconOnly: true },
  "icon-sm": { size: "sm", isIconOnly: true },
  "icon-lg": { size: "lg", isIconOnly: true },
} as const satisfies Record<string, { size: NonNullable<HeroProps["size"]>; isIconOnly: boolean }>;

export interface ButtonProps
  extends Omit<HeroProps, "variant" | "size" | "isIconOnly" | "isDisabled" | "isPending"> {
  variant?: keyof typeof VARIANTS;
  size?: keyof typeof SIZES;
  loading?: boolean;
  disabled?: boolean;
}

export function Button({
  variant = "default",
  size = "default",
  loading = false,
  disabled = false,
  children,
  ...props
}: ButtonProps): React.ReactElement {
  return (
    <HeroButton
      {...props}
      {...SIZES[size]}
      variant={VARIANTS[variant]}
      isDisabled={loading || disabled}
      data-loading={loading ? "" : undefined}
    >
      {(renderProps) => (
        <>
          {typeof children === "function" ? children(renderProps) : children}
          {loading && <Spinner className="size-4" />}
        </>
      )}
    </HeroButton>
  );
}
