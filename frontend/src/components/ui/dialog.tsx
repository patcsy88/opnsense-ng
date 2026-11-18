import { Modal } from "@heroui/react";
import { createContext, useContext, type ComponentProps, type ReactElement, type ReactNode } from "react";
import { cn } from "@/lib/utils";

// Our `Dialog open onOpenChange` API is kept (ADR-0025); HeroUI's Modal is used inside.
interface DialogState {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}
const DialogContext = createContext<DialogState | null>(null);

export function Dialog({ open, onOpenChange, children }: DialogState & { children: ReactNode }): ReactElement {
  return <DialogContext.Provider value={{ open, onOpenChange }}>{children}</DialogContext.Provider>;
}

export function DialogContent({ className, children, ...props }: ComponentProps<typeof Modal.Dialog>): ReactElement {
  const state = useContext(DialogContext);
  if (!state) throw new Error("DialogContent must be used inside Dialog");
  return (
    <Modal.Backdrop isOpen={state.open} onOpenChange={state.onOpenChange}>
      <Modal.Container scroll="inside">
        <Modal.Dialog className={cn("p-6", className)} {...props}>
          {children}
        </Modal.Dialog>
      </Modal.Container>
    </Modal.Backdrop>
  );
}

export function DialogHeader({ className, ...props }: ComponentProps<"div">): ReactElement {
  return <div className={cn("flex flex-col gap-1 pb-3", className)} {...props} />;
}

export function DialogTitle({ className, ...props }: ComponentProps<typeof Modal.Heading>): ReactElement {
  return <Modal.Heading className={cn("text-lg font-semibold", className)} {...props} />;
}

export function DialogDescription({ className, ...props }: ComponentProps<"p">): ReactElement {
  return <p className={cn("text-sm text-muted-foreground", className)} {...props} />;
}

export function DialogFooter({
  className,
  variant,
  ...props
}: ComponentProps<"div"> & { variant?: "default" | "bare" }): ReactElement {
  return (
    <div
      data-variant={variant}
      className={cn("flex flex-col-reverse gap-2 pt-4 sm:flex-row sm:justify-end", className)}
      {...props}
    />
  );
}
