---
name: webui-lib-dir-gitignore-trap
description: services/webui/.gitignore has a bare `lib/` pattern that silently swallows any NEW file placed in src/client/lib/
metadata:
  type: project
---

`services/webui/.gitignore` contains a bare, unanchored `lib/` line. Git's
`.gitignore` matches a bare directory-name pattern anywhere in the tree, so
it ignores the entire `src/client/lib/` directory. Pre-existing tracked
files there (`api.ts`, `apiDarwin.ts`, `apiIceBox.ts`) stay tracked because
git never retroactively un-tracks already-committed files — but any **new**
file added under `src/client/lib/` is silently excluded from `git status`
and `git add` with no error or warning.

**Why:** discovered while adding a new pure-helpers module for the SVID TTL
settings feature — `git status` never showed the new file at all after
placing it in `lib/`. `git check-ignore -v <path>` confirmed the match
against `.gitignore:17:lib/`. Easy to lose work silently: the file exists on
disk, builds and tests pass locally, but it never reaches version control
and a fresh clone breaks.

**How to apply:** never add a new file to `services/webui/src/client/lib/`.
Use `src/client/utils/` (new dir, not ignored) or another existing
non-ignored directory (`components/`, `api/`, `types/`, `hooks/`) for new
webui client code. Before adding any new file anywhere in this repo, a quick
`git check-ignore -v <path>` after creation is cheap insurance. This is a
`.gitignore` bug worth flagging to the user for a proper fix (e.g. anchor it
to `/dist/lib/` or whatever it was actually meant to exclude) but do not fix
it unilaterally as part of an unrelated feature — it's out of scope and the
intent behind the line is unknown.
