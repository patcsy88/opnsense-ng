import { DropdownMenu as M } from "radix-ui";
import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

export const DropdownMenu = M.Root;
export const DropdownMenuTrigger = M.Trigger;
export const DropdownMenuLabel = ({ className, ...p }: ComponentProps<typeof M.Label>) => (
  <M.Label className={cn("px-2 py-1.5 text-xs text-muted-foreground", className)} {...p} />
);
export const DropdownMenuSeparator = () => <M.Separator className="my-1 h-px bg-border" />;
export function DropdownMenuContent({ className, ...props }: ComponentProps<typeof M.Content>) {
  return (
    <M.Portal>
      <M.Content
        align="end"
        sideOffset={6}
        className={cn("z-50 min-w-40 rounded-md border border-border bg-card p-1 shadow-md", className)}
        {...props}
      />
    </M.Portal>
  );
}
export function DropdownMenuItem({ className, ...props }: ComponentProps<typeof M.Item>) {
  return (
    <M.Item
      className={cn("flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-muted", className)}
      {...props}
    />
  );
}
