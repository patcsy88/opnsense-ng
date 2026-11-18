import type React from "react";
import { cn } from "@/lib/utils";

// Plain HTML tables styled with HeroUI's theme variables (ADR-0025). The React Aria Table needs
// a different data model, and these pages only list rows, so native table markup is kept.
export type TableVariant = "default" | "card";

export type TableProps = React.ComponentProps<"table"> & {
  variant?: TableVariant;
};

export function Table({ className, variant = "default", ...props }: TableProps): React.ReactElement {
  return (
    <div className="relative w-full overflow-x-auto" data-slot="table-container" data-variant={variant}>
      <table className={cn("w-full caption-bottom text-sm", className)} data-slot="table" {...props} />
    </div>
  );
}

export function TableHeader({ className, ...props }: React.ComponentProps<"thead">): React.ReactElement {
  return <thead className={cn("[&_tr]:border-b", className)} data-slot="table-header" {...props} />;
}

export function TableBody({ className, ...props }: React.ComponentProps<"tbody">): React.ReactElement {
  return <tbody className={cn("[&_tr:last-child]:border-0", className)} data-slot="table-body" {...props} />;
}

export function TableFooter({ className, ...props }: React.ComponentProps<"tfoot">): React.ReactElement {
  return (
    <tfoot
      className={cn("border-t bg-default/40 font-medium [&>tr]:last:border-b-0", className)}
      data-slot="table-footer"
      {...props}
    />
  );
}

export function TableRow({ className, ...props }: React.ComponentProps<"tr">): React.ReactElement {
  return (
    <tr
      className={cn("border-b border-border transition-colors hover:bg-default/40 data-[state=selected]:bg-default", className)}
      data-slot="table-row"
      {...props}
    />
  );
}

export function TableHead({ className, ...props }: React.ComponentProps<"th">): React.ReactElement {
  return (
    <th
      className={cn("h-10 whitespace-nowrap px-2.5 text-left align-middle font-medium leading-none text-muted-foreground", className)}
      data-slot="table-head"
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: React.ComponentProps<"td">): React.ReactElement {
  return (
    <td
      className={cn("whitespace-nowrap p-2.5 align-middle leading-none", className)}
      data-slot="table-cell"
      {...props}
    />
  );
}

export function TableCaption({ className, ...props }: React.ComponentProps<"caption">): React.ReactElement {
  return <caption className={cn("mt-4 text-sm text-muted-foreground", className)} data-slot="table-caption" {...props} />;
}
