import { Input as HeroInput } from "@heroui/react";
import type * as React from "react";

// HeroUI's Input has a 16px minimum on small screens through its own styles; iOS does not zoom
// on focus (checked by e2e/ios.spec.ts). Our `size` prop was not used outside this folder.
export type InputProps = React.ComponentProps<typeof HeroInput>;

export function Input({ className, ...props }: InputProps): React.ReactElement {
  return <HeroInput fullWidth className={className} {...props} />;
}
