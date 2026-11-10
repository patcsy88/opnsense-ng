import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/features/auth/auth";

export function AdministrationPage() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Administration</h1>
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Firewall Connections</CardTitle>
            <CardDescription>Manage the OPNsense instances this app connects to.</CardDescription>
          </CardHeader>
          <CardContent>
            {admin ? (
              <Link className="text-sm text-primary underline" to="/administration/firewalls">
                Open
              </Link>
            ) : (
              <Badge>Administrators only</Badge>
            )}
          </CardContent>
        </Card>
        {["Users", "Audit log"].map((t) => (
          <Card key={t}>
            <CardHeader>
              <CardTitle>{t}</CardTitle>
            </CardHeader>
            <CardContent>
              <Badge>Planned</Badge>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
