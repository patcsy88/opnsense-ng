import { Label as HeroLabel } from "@heroui/react";
import type * as React from "react";

export function Label(props: React.ComponentProps<typeof HeroLabel>): React.ReactElement {
  return <HeroLabel {...props} />;
}
