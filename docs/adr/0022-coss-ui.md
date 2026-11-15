# ADR-0022: Move the UI to coss ui (Base UI)

- Status: accepted (answers and dependencies approved by project owner on 2026-11-15)
- Date: 2026-11-15
- Deciders: project owner

## Context

The UI uses shadcn/ui components on Radix (`radix-ui` 1.8.1) with Tailwind CSS 4. The user asked to change the UI to "COSS", meaning coss ui (coss.com/ui): a copy-paste component library from Cal.com, built on Base UI and Tailwind CSS 4, with shadcn-compatible CSS variables and a shadcn registry.

Current surface: 12 files in `frontend/src/components/ui` (badge, button, card, confirm-dialog, dialog, dropdown-menu, input, label, sheet, status-badge, table), 44 files import from them, and only 4 use Radix directly (Dialog, DropdownMenu, Label, Slot). Engine and section tabs are hand-built buttons, and selects are native `<select>`.

Owner decisions (2026-11-15): full migration, `@base-ui/react` may be added, adopt Inter and Geist Mono, move form selects to coss Select, and no page is excluded.

## Decision

1. Copy coss ui components into `frontend/src/components/ui` (copy-paste, no runtime package), using the shadcn CLI or by hand. Keep our file names and import paths (`@/components/ui/...`) so the 44 call sites change little.
2. Add `@base-ui/react` 1.9.0 (MIT, pinned exact), plus the two fontsource packages above. Remove `radix-ui` once nothing imports it. `class-variance-authority`, `clsx`, `tailwind-merge` and `lucide-react` stay.
3. Adopt the coss colour tokens (neutral set plus `--destructive-foreground`, `--info`, `--success`, `--warning` and their foregrounds) in `index.css`, mapped to our existing token names so dark mode and the theme toggle keep working.
4. Fonts: Inter (`--font-sans`, `--font-heading`) and Geist Mono (`--font-mono`), self-hosted through the build with `@fontsource-variable/inter` and `@fontsource-variable/geist-mono` (OFL-1.1, latin subset imported only). No runtime font request, and the service worker still caches static assets only.
5. Migrate in phases, each independently shippable with tests green:
   - A. Tokens, fonts and base styles.
   - B. Primitives: Button, Input, Label, Badge, Card, Table.
   - C. Overlays: Dialog, AlertDialog (replacing `ConfirmDialog`), Sheet, Menu (replacing `dropdown-menu`).
   - D. Tabs for the engine and section selectors, and coss Select for every native `<select>`, including those in forms. Form code that reads `FormData` needs a `name` on the Select, which Base UI supports.
   - E. Page-level polish: layout, sidebar, empty states, spinners.
6. Behaviour stays identical: roles, staging, typed confirmations, CSRF and error handling are untouched. This is a visual and primitive change only.

## Consequences

- Base UI is younger than Radix and its API differs (for example `render` instead of `asChild`, different dialog and menu parts). Tests that rely on Radix roles and focus behaviour may need adjusting, but the user-visible behaviour must not change.
- Bundle size should not grow materially (Radix is removed), but the main chunk is already about 540 kB, so check it per phase.
- Licence: coss ui is MIT (verified in the `cosscom/ui` LICENSE file, 2026-11-15), Base UI is MIT, the fonts are OFL-1.1. The copied files keep their copyright notice, recorded in `frontend/THIRD_PARTY.md`.
- The service worker and the `check-sw` build step must still pass: no new runtime fetches and no API caching.
- Existing e2e and live specs use role and label selectors, so they should survive; they will be rerun after phases C and D.
- ADR-0003's dependency list gains `@base-ui/react` and loses `radix-ui`.

## Alternatives considered

- Look only: keep Radix and restyle with coss tokens. Cheapest, but it is not "coss ui" and leaves two design systems in mind.
- Pilot one area first: lower risk, but the surface is small enough that phased full migration gives the same safety.
- shadcn/ui on Base UI: closer to what we have, but not what was asked for.
