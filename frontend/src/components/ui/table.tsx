import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function Table({ className, ...props }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full text-left text-sm", className)} {...props} />
    </div>
  );
}
export const TableHeader = (p: HTMLAttributes<HTMLTableSectionElement>) => <thead className="border-b border-border" {...p} />;
export const TableBody = (p: HTMLAttributes<HTMLTableSectionElement>) => <tbody {...p} />;
export const TableRow = ({ className, ...p }: HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b border-border last:border-0", className)} {...p} />
);
export const TableHead = ({ className, ...p }: ThHTMLAttributes<HTMLTableCellElement>) => (
  <th className={cn("px-3 py-2 font-medium text-muted-foreground", className)} {...p} />
);
export const TableCell = ({ className, ...p }: TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("px-3 py-2 align-middle", className)} {...p} />
);
