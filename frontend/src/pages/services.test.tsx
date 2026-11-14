import { fireEvent, screen, within } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const body = (verified = true) => ({
  firewall_id: FW.id,
  services: [
    {
      id: "unbound",
      name: "unbound",
      description: "Unbound DNS",
      running: true,
      locked: false,
    },
    {
      id: "dnsmasq",
      name: "dnsmasq",
      description: "Dnsmasq DNS/DHCP",
      running: false,
      locked: true,
    },
  ],
  truncated: false,
  registry_verified: verified,
});

function services(
  user: object,
  data: JsonBodyType = body(),
  status = 200,
  writes = false,
) {
  server.use(
    http.get("/api/v1/firewalls", () =>
      HttpResponse.json([{ ...FW, allow_writes: writes }]),
    ),
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/services`, () =>
      HttpResponse.json(data, { status }),
    ),
  );
}

describe("Services page", () => {
  it("shows running and stopped services with no control buttons, for any role", async () => {
    services(READER);
    renderApp(<App />, "/services");
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(screen.getByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText("locked")).toBeInTheDocument();
    expect(screen.getByText(/1 not running/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /start|stop|restart/i }),
    ).not.toBeInTheDocument();
  });

  it("filters by name or description", async () => {
    services(ADMIN);
    renderApp(<App />, "/services");
    await screen.findByText("Running");
    fireEvent.change(screen.getByLabelText("Filter services"), {
      target: { value: "dhcp" },
    });
    expect(screen.queryByText("Unbound DNS")).not.toBeInTheDocument();
    expect(screen.getByText("Dnsmasq DNS/DHCP")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter services"), {
      target: { value: "zzz" },
    });
    expect(screen.getByText("No services match.")).toBeInTheDocument();
  });

  it("marks an unverified capability and reports firewall errors", async () => {
    services(ADMIN, body(false));
    renderApp(<App />, "/services");
    expect(await screen.findByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the call fails", async () => {
    services(
      ADMIN,
      { detail: { status: "unreachable", message: "Firewall is unreachable" } },
      502,
    );
    renderApp(<App />, "/services");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });

  describe("service control (ADR-0016)", () => {
    const list = {
      ...body(),
      services: [
        {
          id: "ntpd",
          name: "ntpd",
          description: "NTP",
          running: true,
          locked: false,
        },
        {
          id: "cron",
          name: "cron",
          description: "Cron",
          running: false,
          locked: false,
        },
        {
          id: "webgui",
          name: "webgui",
          description: "Web GUI",
          running: true,
          locked: false,
        },
        {
          id: "pf",
          name: "pf",
          description: "Packet filter",
          running: true,
          locked: true,
        },
      ],
    };
    const result = (over: object = {}) => ({
      firewall_id: FW.id,
      service: "cron",
      instance: null,
      action: "start",
      was_running: false,
      running: true,
      confirmed: true,
      message: "Running, confirmed",
      ...over,
    });

    it("shows no buttons when writes are off, and says why", async () => {
      services(ADMIN, list, 200, false);
      renderApp(<App />, "/services");
      await screen.findByText("ntpd");
      expect(
        await screen.findByText(/enable changes for this firewall/),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /^(start|stop|restart)$/i }),
      ).not.toBeInTheDocument();
    });

    it("shows no buttons to other roles even when writes are on", async () => {
      services(READER, list, 200, true);
      renderApp(<App />, "/services");
      await screen.findByText("ntpd");
      expect(
        screen.queryByRole("button", { name: /^(start|stop|restart)$/i }),
      ).not.toBeInTheDocument();
    });

    it("offers the right buttons and hides them for locked and management services", async () => {
      services(ADMIN, list, 200, true);
      renderApp(<App />, "/services");
      await screen.findByText("ntpd");
      expect(
        await screen.findAllByRole("button", { name: "Stop" }),
      ).toHaveLength(1); // ntpd only
      expect(screen.getAllByRole("button", { name: "Restart" })).toHaveLength(
        1,
      );
      expect(screen.getAllByRole("button", { name: "Start" })).toHaveLength(1); // cron
      expect(screen.getAllByText("not available here")).toHaveLength(2); // pf (locked), webgui
    });

    it("starts a service after a plain confirm and shows the read-back result", async () => {
      services(ADMIN, list, 200, true);
      document.cookie = "csrf_token=tok; path=/";
      let sent: unknown = null;
      server.use(
        http.post(
          `/api/v1/firewalls/${FW.id}/services/start`,
          async ({ request }) => {
            sent = await request.json();
            return HttpResponse.json(result());
          },
        ),
      );
      renderApp(<App />, "/services");
      fireEvent.click(await screen.findByRole("button", { name: "Start" }));
      const dialog = await screen.findByRole("alertdialog");
      expect(within(dialog).queryByLabelText(/Type/)).not.toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole("button", { name: "Start" }));
      expect(
        await screen.findByText("cron: Running, confirmed"),
      ).toBeInTheDocument();
      expect(sent).toMatchObject({ service: "cron", instance: null });
    });

    it("needs the name typed to stop a high-impact service", async () => {
      services(ADMIN, list, 200, true);
      document.cookie = "csrf_token=tok; path=/";
      let sent: Record<string, unknown> | null = null;
      server.use(
        http.post(
          `/api/v1/firewalls/${FW.id}/services/stop`,
          async ({ request }) => {
            sent = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json(
              result({
                service: "ntpd",
                action: "stop",
                running: false,
                confirmed: false,
                message:
                  "Not confirmed: still running after 10 s. Check again shortly.",
              }),
            );
          },
        ),
      );
      renderApp(<App />, "/services");
      fireEvent.click(await screen.findByRole("button", { name: "Stop" }));
      const confirm = within(await screen.findByRole("alertdialog")).getByRole(
        "button",
        { name: "Stop" },
      );
      expect(confirm).toBeDisabled();
      fireEvent.change(screen.getByLabelText(/Type/), {
        target: { value: "ntpd" },
      });
      expect(confirm).toBeEnabled();
      fireEvent.click(confirm);
      expect(
        await screen.findByText(/Not confirmed: still running/),
      ).toBeInTheDocument();
      expect(sent).toMatchObject({ service: "ntpd", confirm_name: "ntpd" });
    });

    it("shows the refusal from the backend in the dialog", async () => {
      services(ADMIN, list, 200, true);
      document.cookie = "csrf_token=tok; path=/";
      server.use(
        http.post(`/api/v1/firewalls/${FW.id}/services/restart`, () =>
          HttpResponse.json(
            { detail: "Another service action is running on this firewall" },
            { status: 409 },
          ),
        ),
      );
      renderApp(<App />, "/services");
      fireEvent.click(await screen.findByRole("button", { name: "Restart" }));
      const dialog = await screen.findByRole("alertdialog");
      fireEvent.change(within(dialog).getByLabelText(/Type/), {
        target: { value: "ntpd" },
      });
      fireEvent.click(within(dialog).getByRole("button", { name: "Restart" }));
      expect(await within(dialog).findByRole("alert")).toHaveTextContent(
        /Another service action/,
      );
    });
  });
});
