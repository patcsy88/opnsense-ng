import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ThemeToggle } from "@/components/theme-toggle";
import { ThemeProvider, THEME_KEY } from "./theme";

function setup() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

async function choose(label: string) {
  const trigger = screen.getByRole("button", { name: /theme/i });
  fireEvent.keyDown(trigger, { key: "Enter" });
  fireEvent.click(await screen.findByText(label));
}

describe("theme", () => {
  it("defaults to system and follows matchMedia (light in jsdom)", () => {
    setup();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(screen.getByRole("button", { name: "Theme: system" })).toBeInTheDocument();
  });

  it("applies and persists only the preference", async () => {
    setup();
    await choose("Dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(localStorage.length).toBe(1);
  });

  it("restores a stored preference", () => {
    localStorage.setItem(THEME_KEY, "dark");
    setup();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
