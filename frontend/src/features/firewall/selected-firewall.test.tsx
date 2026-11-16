import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, chooseOption, renderApp } from "@/test/utils";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

function setup(seen: string[]) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([
        { id: A, name: "alpha-fw" },
        { id: B, name: "bravo-fw" },
      ]),
    ),
    http.get("/api/v1/firewalls/:id/interfaces", ({ params }) => {
      seen.push(String(params.id));
      return HttpResponse.json({
        firewall_id: params.id,
        interfaces: [],
        registry_verified: true,
      });
    }),
    http.get("/api/v1/firewalls/:id/traffic", ({ params }) => {
      seen.push(String(params.id));
      return HttpResponse.json({
        firewall_id: params.id,
        time: null,
        interfaces: [],
        registry_verified: true,
      });
    }),
  );
}

describe("shared firewall choice", () => {
  beforeEach(() => sessionStorage.clear());

  it("keeps the chosen firewall when moving between pages", async () => {
    const seen: string[] = [];
    setup(seen);
    renderApp(<App />, "/network");
    const picker = await screen.findByLabelText("Firewall");
    await waitFor(() => expect(seen).toContain(A));
    await chooseOption(picker, "bravo-fw");
    await waitFor(() => expect(seen).toContain(B));

    fireEvent.click(screen.getAllByRole("link", { name: "Traffic" })[0]!);
    await waitFor(() =>
      expect(seen.filter((id) => id === B).length).toBeGreaterThan(1),
    );
    expect(screen.getByLabelText("Firewall")).toHaveTextContent("bravo-fw");
    expect(sessionStorage.getItem("selected-firewall")).toBe(B);
  });
});
