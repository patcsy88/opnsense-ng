import { Construction } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function PlannedPage({ title }: { title: string }) {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">{title}</h1>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Construction className="h-4 w-4" aria-hidden /> <Badge>Planned</Badge>
          </CardTitle>
          <CardDescription>This section is not implemented yet.</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          No data is shown here. It will appear once the backend supports these operations.
        </CardContent>
      </Card>
    </div>
  );
}
