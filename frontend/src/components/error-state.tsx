import { AlertTriangle, WifiOff } from "lucide-react";
import { ApiError } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const d = describeError(error);
  const offline = error instanceof ApiError && error.kind === "network";
  const Icon = offline ? WifiOff : AlertTriangle;
  return (
    <div role="alert" className="flex flex-col items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-4">
      <div className="flex items-center gap-2 font-medium text-destructive">
        <Icon className="h-4 w-4" aria-hidden />
        {d.title}
      </div>
      <p className="text-sm">{d.message}</p>
      {d.retryable && onRetry && (
        <Button size="sm" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}
