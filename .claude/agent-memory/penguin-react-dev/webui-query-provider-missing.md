---
name: webui-query-provider-missing
description: TanStack Query is used in the vault module (useQuery/useMutation/useQueryClient) but no QueryClientProvider exists anywhere in the webui app tree
metadata:
  type: project
---

`services/webui` declares `@tanstack/react-query` and several vault-module
components (`src/client/modules/vault/JitAccess.tsx`, `CloudSync.tsx`,
`Secrets.tsx`, `SettingsPage.tsx`) call `useQuery`/`useMutation`/
`useQueryClient`. There is no `QueryClientProvider` anywhere in
`src/client/main.tsx` or `App.tsx` — grepped the whole client tree, zero
matches. `useQueryClient()` throws immediately ("No QueryClient set") if
rendered without a provider in the tree.

**Why:** none of the vault module components have tests (`src/client/tests/`
has zero vault test files as of 2026-07-31), so this has apparently never
been exercised and never caught. It's a latent bug, not a working pattern to
imitate.

**How to apply:** for new "core" (non-vault) app components in this webui —
pages like `Spire.tsx`, `Settings.tsx`, `Users.tsx` — follow their existing,
actually-working convention: plain `useState`/`useEffect` for data fetching
via the centralized `api` client, not `useQuery`. This deviates from the
default PenguinTech "TanStack Query for all server state" identity rule, but
matches what's proven to work in this specific file family and avoids
introducing an untested dependency on missing provider wiring. If a task
specifically needs TanStack Query, add a `QueryClientProvider` to
`main.tsx` first (and flag that you're doing so) rather than assuming one
exists.
