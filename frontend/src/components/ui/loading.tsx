import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";

/** Status line with a decorative spinner; the text stays the accessible name. */
export function Loading({ className }: { className?: string }) {
  return (
    <p role="status" className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)}>
      <Spinner aria-hidden role="presentation" aria-label={undefined} className="size-4" />
      Loading…
    </p>
  );
}
