import { act, screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, chooseOption, renderApp } from "@/test/utils";
import { RATE_KEY } from "@/features/traffic/update-rate";

const sample = (verified = true) => ({
  firewall_id: FW.id,
  time: 1762950000.5,
  interfaces: [
    { interface: "wan", name: "WAN", in_bytes: 1000, out_bytes: 2000, in_packets: 10, out_packets: 20 },
    { interface: "lan", name: null, in_bytes: 5, out_bytes: 6, in_packets: 1, out_packets: 1 },
  ],
  registry_verified: verified,
});

function traffic(user: object, body: JsonBodyType = sample(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/traffic`, () => HttpResponse.json(body, { status })),
  );
}

describe("Traffic page", () => {
  it("lists every interface and waits for a second sample before showing a rate", async () => {
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    expect(await screen.findByRole("heading", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "lan" })).toBeInTheDocument();
    expect(screen.getAllByText("…").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Collecting samples…")).toHaveLength(2);
  });

  it("marks an unverified capability", async () => {
    traffic(ADMIN, sample(false));
    renderApp(<App />, "/traffic");
    expect(await screen.findByRole("cell", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the firewall call fails", async () => {
    traffic(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/traffic");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });

  it("is not reachable for read-only users", async () => {
    traffic(READER);
    renderApp(<App />, "/traffic");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByText("Interface traffic")).not.toBeInTheDocument();
  });
});

class FakeEventSource {
  static all: FakeEventSource[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: MessageEvent<string>) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  listeners = new Map<string, () => void>();
  constructor(public url: string) {
    FakeEventSource.all.push(this);
  }
  addEventListener(name: string, fn: () => void) {
    this.listeners.set(name, fn);
  }
  close() {
    this.closed = true;
  }
  send(body: object) {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(body) }));
  }
}

function first(): FakeEventSource {
  const es = FakeEventSource.all[0];
  if (!es) throw new Error("no stream was opened");
  return es;
}

describe("Traffic page live stream", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    FakeEventSource.all = [];
  });

  it("draws from the stream and does not poll while it is open", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    let polls = 0;
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/firewalls/${FW.id}/traffic`, () => {
        polls += 1;
        return HttpResponse.json(sample());
      }),
    );
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    const es = first();
    expect(es.url).toBe(`/api/v1/firewalls/${FW.id}/traffic/stream`);
    act(() => es.onopen?.());
    act(() => es.send(sample()));
    expect(await screen.findByRole("heading", { name: "WAN" })).toBeInTheDocument();
    act(() => es.send({ ...sample(), time: 1762950001.5 }));
    expect(await screen.findAllByText(/bit\/s/)).not.toHaveLength(0);
    expect(polls).toBe(0);
  });

  it("ignores a sample for another firewall and a malformed one", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    );
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    const es = first();
    act(() => es.onopen?.());
    act(() => es.send({ ...sample(), firewall_id: "00000000-0000-4000-8000-000000000000" }));
    act(() => es.onmessage?.(new MessageEvent("message", { data: "not json" })));
    expect(screen.queryByRole("heading", { name: "WAN" })).not.toBeInTheDocument();
  });

  it("falls back to polling when the stream fails", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    const es = first();
    act(() => es.onerror?.());
    expect(es.closed).toBe(true);
    expect(await screen.findByRole("heading", { name: "WAN" })).toBeInTheDocument();
  });

  it("reopens the stream when the server ends it", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    const es = first();
    act(() => es.listeners.get("end")?.());
    expect(es.closed).toBe(true);
    expect(FakeEventSource.all).toHaveLength(2);
  });

  it("closes the stream when the page is left", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    const view = renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    view.unmount();
    expect(first().closed).toBe(true);
  });
});

describe("Traffic update rate", () => {
  beforeEach(() => localStorage.removeItem(RATE_KEY));
  afterEach(() => {
    vi.unstubAllGlobals();
    FakeEventSource.all = [];
    localStorage.removeItem(RATE_KEY);
  });

  const at = (t: number, inBytes: number) => ({
    ...sample(),
    time: t,
    interfaces: [{ interface: "wan", name: "WAN", in_bytes: inBytes, out_bytes: 0, in_packets: 1, out_packets: 1 }],
  });

  it("defaults to live and remembers the choice", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    const picker = await screen.findByRole("button", { name: /Update rate/ });
    expect(picker).toHaveTextContent("Live (1 s)");
    await chooseOption(picker, "Every 5 s");
    expect(localStorage.getItem(RATE_KEY)).toBe("5");
    expect(screen.getByRole("button", { name: /Update rate/ })).toHaveTextContent("Every 5 s");
  });

  it("starts from a remembered choice and ignores a bad stored value", async () => {
    localStorage.setItem(RATE_KEY, "10");
    traffic(ADMIN);
    const view = renderApp(<App />, "/traffic");
    expect(await screen.findByRole("button", { name: /Update rate/ })).toHaveTextContent("Every 10 s");
    view.unmount();
    localStorage.setItem(RATE_KEY, "bogus");
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    expect(await screen.findByRole("button", { name: /Update rate/ })).toHaveTextContent("Live (1 s)");
  });

  it("draws only every Nth second of the stream", async () => {
    localStorage.setItem(RATE_KEY, "5");
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    const es = first();
    act(() => es.onopen?.());
    act(() => es.send(at(100, 0)));
    for (const t of [101, 102, 103, 104]) act(() => es.send(at(t, t * 1000)));
    expect(await screen.findByRole("heading", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByText("Collecting samples…")).toBeInTheDocument(); // still one sample drawn
    act(() => es.send(at(105, 105000)));
    act(() => es.send(at(107, 107000))); // too soon after 105: not drawn
    act(() => es.send(at(110, 110000)));
    expect(await screen.findByRole("img", { name: "Traffic graph for WAN" })).toBeInTheDocument();
  });

  it("closes the stream while paused and opens it again on resume", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(1));
    await chooseOption(await screen.findByRole("button", { name: /Update rate/ }), "Paused");
    expect(first().closed).toBe(true);
    expect(localStorage.getItem(RATE_KEY)).toBe("paused");
    expect(await screen.findByText(/Paused\. Choose an update rate/)).toBeInTheDocument();
    await chooseOption(screen.getByRole("button", { name: /Update rate/ }), "Live (1 s)");
    await vi.waitFor(() => expect(FakeEventSource.all).toHaveLength(2));
  });

  it("does not poll the firewall while paused", async () => {
    localStorage.setItem(RATE_KEY, "paused");
    let polls = 0;
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/firewalls/${FW.id}/traffic`, () => {
        polls += 1;
        return HttpResponse.json(sample());
      }),
    );
    renderApp(<App />, "/traffic");
    expect(await screen.findByText(/Paused\. Choose an update rate/)).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 200));
    expect(polls).toBe(0);
  });
});

