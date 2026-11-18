import { TextArea as HeroTextArea } from "@heroui/react";
import type * as React from "react";

export type TextareaProps = React.ComponentProps<typeof HeroTextArea>;

export function Textarea({ className, ...props }: TextareaProps): React.ReactElement {
  return <HeroTextArea fullWidth className={className} {...props} />;
}
