# ADR-0025: HeroUI replaces coss ui

- Status: accepted (approved by project owner on 2026-11-18); implementation in progress on the `heroui` branch
- Date: 2026-11-18
- Deciders: project owner
- Supersedes: ADR-0022

## Context

ADR-0022 adopted coss ui, copied into `frontend/src/components/ui` on Base UI. The owner wants HeroUI v3 instead. HeroUI v3 is stable (3.2.7 at the time of writing), Apache 2.0, built on Tailwind CSS v4 and React Aria Components, and ships as a library, so updates arrive through the package rather than copied files.

## Decision

- Add `@heroui/react` and `@heroui/styles` (exact pins, per `.npmrc`) and the React Aria packages they list as peer dependencies: `react-aria`, `react-aria-components`, `@react-aria/ssr`, `@react-aria/utils`, `@internationalized/date`.
- Replace the 21 files in `src/components/ui` with wrappers over HeroUI. Exported names and props stay as close to today's as possible, so the roughly 50 consuming files change little. Behaviour is unchanged: roles, staging, typed confirmations, CSRF and error handling stay as they are.
- HeroUI's variables own the theme. The `.dark` class still switches it. Our old token names (`text-muted-foreground`, `bg-card`, `text-destructive`, and so on) stay as aliases onto HeroUI variables. Names that clash with HeroUI's own (`muted`, `accent`) are migrated at the call sites.
- Remove `@base-ui/react` and `class-variance-authority` when nothing imports them. Update `THIRD_PARTY.md` (Apache 2.0 notice).
- Work happens on the `heroui` branch, in small commits per component group. `main` is untouched until the owner merges.

## Consequences

- Event and prop names change inside the wrappers (`onPress`, `isDisabled`, key-based selection). React Aria opens selects and menus differently from Base UI, so the test helpers `chooseOption` and Playwright `pick` are rewritten.
- The look changes. The owner reviews it by eye after the migration, since automated tests cover behaviour and structure only.
- The bundle size is measured before and after.
- npm audit shows the same 22 findings before and after adding the packages (all pre-existing, dev tooling).
