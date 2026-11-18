import { AlertDialog } from "@heroui/react";
import { useState, type ReactNode } from "react";
import { Button } from "./button";
import { Input } from "./input";

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  /** When set, the user must type this exact text before confirming (extra confirmation). */
  requireText?: string;
  pending?: boolean;
  error?: string | null;
  onConfirm: () => void;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  destructive = false,
  requireText,
  pending = false,
  error,
  onConfirm,
}: ConfirmDialogProps) {
  const [typed, setTyped] = useState("");
  const blocked = pending || (requireText !== undefined && typed !== requireText);
  return (
    <AlertDialog.Backdrop
      isOpen={open}
      onOpenChange={(o) => {
        if (!o) setTyped("");
        onOpenChange(o);
      }}
    >
      <AlertDialog.Container>
        <AlertDialog.Dialog className="p-6">
          <AlertDialog.Header className="flex flex-col gap-1 pb-3">
            <AlertDialog.Heading className="text-lg font-semibold">{title}</AlertDialog.Heading>
            <div className="text-sm text-muted-foreground">{description}</div>
          </AlertDialog.Header>
          {requireText !== undefined && (
            <div className="space-y-1">
              <label htmlFor="confirm-text" className="text-sm">
                Type <strong>{requireText}</strong> to confirm
              </label>
              <Input id="confirm-text" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </div>
          )}
          {error && (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {error}
            </p>
          )}
          <AlertDialog.Footer className="flex flex-col-reverse gap-2 pt-4 sm:flex-row sm:justify-end">
            <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              Cancel
            </Button>
            <Button variant={destructive ? "destructive" : "default"} onClick={onConfirm} disabled={blocked}>
              {pending ? "Working…" : confirmLabel}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
