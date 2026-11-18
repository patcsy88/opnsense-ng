import type { Locator, Page } from "@playwright/test";

/** Picks an option in a HeroUI Select (a button that opens a popup listbox). */
export async function pick(page: Page, trigger: Locator, name: string): Promise<void> {
  await trigger.click();
  await page.getByRole("option", { name, exact: true }).click();
}
