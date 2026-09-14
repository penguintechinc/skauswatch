# Proto Wire-Compat Baseline (v1)

## What this is

Byte-for-byte snapshots of the canonical skauswatch `.proto` contracts
**as compiled into fielded v1 Go ENDPOINT agents**:

| Baseline file | Live file |
|---|---|
| `manager/v1/manager.proto` | `proto/manager/v1/manager.proto` |
| `pki/v1/pki.proto` | `proto/pki/v1/pki.proto` |
| `s3scan/v1/s3_scan.proto` | `proto/s3scan/v1/s3_scan.proto` |

CI (`.github/workflows/proto.yml`) and `scripts/proto/check-breaking.sh` run
`buf breaking proto --against proto/baseline` using buf's **FILE** breaking
rules (wire + JSON + generated-source compatibility). Any change to the live
`proto/` tree that would break compatibility against this snapshot fails CI.

The packages here are intentionally unversioned (`skauswatch.manager`,
`skauswatch.s3scan`, `skauswatch.pki`) — the package name is part of the gRPC
method path and cannot change without breaking every deployed agent. This
directory is its own buf module (`buf.yaml` here) precisely so the identical
package names in the live tree and the baseline never collide: the live
module at `proto/buf.yaml` excludes `baseline/`.

## NEVER edit these files by hand

This baseline is the compatibility contract with software already running on
customer endpoints. Editing it by hand silently moves the goalposts and lets
a wire-breaking change through CI undetected.

- Do **not** "fix" the baseline to make a red `buf breaking` check green.
- Do **not** reformat, re-lint, or otherwise touch the `.proto` files here.
- Additive, compatible changes to the live protos (new fields at unused
  numbers, new messages, new RPCs) pass the gate **without** touching the
  baseline — the baseline does not need to track the live tree.

## Regenerating the baseline

Regeneration is only legitimate after an **explicit wire-compat review** that
concludes the fielded-agent contract itself has moved (e.g. all v1 agents are
EOL, or a coordinated protocol migration has completed and been signed off).
It is a reviewed decision, never a mechanical fix:

1. Open an issue documenting why the fielded contract changed and which agent
   versions remain in the field.
2. Get sign-off from the manager + agent owners (wire-compat review).
3. Copy the live protos over the baseline (byte copies, same relative paths).
4. Land the baseline update in its own PR referencing the review issue.
