# YARA-X Compatibility Spike — Verdict

**Decision:** Can pure-Rust `yara-x` replace libyara (v1: `yara-python==4.5.4`) for skauswatch's actual YARA rule corpus in the v2 `worker-scanner`, or must we fall back to the `yara` FFI crate?

**Verdict: GO — adopt `yara-x`, pinned `=1.19.0`.** 100% compile pass, 100% match parity (rule-level *and* matched-string-level) on a 19-file fixture set, ~13x scan throughput vs libyara, zero C dependencies.

- Spike date: 2026-07-22 · Branch: `release/v2.0.x`
- Engines compared: `yara-x 1.19.0` (crates.io, released 2026-06-24, current stable) vs `yara-python 4.5.4` (v1's exact pin from `services/worker-s3/requirements.txt`, bundled libyara)
- Spike artifacts (code, fixtures, raw results): session scratchpad `yarax-spike/` — reproduction commands in the appendix. Nothing was added to the workspace besides this document.

---

## 1. Corpus inventory

The **entire runtime rule corpus is one file: `config/yara_rules/corporate_threats.yar` — 5 rules.** Verified by:

- Repo-wide search for `*.yar` / `*.yara` on `release/v2.0.x` **and** `release/v1.0.x` (`git ls-tree -r release/v1.0.x | grep -iE '\.yara?$'`) — one file, both branches; git history shows it is the only rule file ever committed.
- v1 loader: `services/worker-s3/scanner/yara_scanner.py` — `yara.compile(rules_path)`, rules path from `YARA_RULES_PATH` (default `/yara_rules`), YARA off by default (`YARA_ENABLED=false`).
- Rule delivery: docker-compose mounts `./config/yara_rules:/yara_rules:ro`; Helm (`k8s/helm/worker-s3/values.yaml`) mounts ConfigMap `yara-rules-config` at `/etc/yara/rules`. **Operators can therefore inject arbitrary rules** — the corpus is small but user-extensible, which is why §3 probes features beyond the corpus.
- No YARA rule feeds exist: `ti/enricher.py` only parses rule *names* out of scan results; threat-intel feeds (VT/OTX) never deliver rule text.

### Per-rule feature usage

| Rule | Strings | Features used |
|---|---|---|
| `EICAR_Test_File` | 1 literal | plain string, meta |
| `Suspicious_PowerShell_Download` | 9 literals | `nocase`, wildcard string sets (`$download*`), `any of` |
| `Suspicious_Office_Macro` | 8 literals | `nocase`, wildcard sets, boolean combos |
| `Base64_Encoded_PE` | 3 literals | `any of ($b64_mz*)` |
| `Cryptocurrency_Miner_Strings` | 5 literals + 2 regexes | `nocase`, unanchored regexes (BTC/XMR address patterns), `N of` counting |

**Not used anywhere in the corpus:** modules (`pe`/`elf`/`math`/`hash`/…), external variables, `include`, hex strings, `wide`/`xor`/`base64` modifiers, `entrypoint`, `filesize`, loops. The corpus sits entirely in yara-x's best-supported subset.

### v1 defect found during inventory (Phase 3 input)

`YaraScanner` requires a single rules **file** (`yara.compile(filepath)`), but the config default (`/yara_rules`), Helm mount (`/etc/yara/rules`), and docs all point at a **directory**. `yara.compile(<dir>)` raises, `worker.py:478-489` swallows the exception (`logger.warning` → `yara_scanner = None`), so **v1 YARA scanning silently no-ops under the default/Helm deployment layout** unless `YARA_RULES_PATH` names one `.yar` file. v2 `worker-scanner` must glob `*.yar`/`*.yara` under the rules dir (each file = one `Compiler::add_source`), and must treat rule-load failure as a hard, visible error (metric + log), not a silent disable. This is a behavioral *improvement*, to be recorded alongside the other documented v1 defects in `docs/v2-port/manager-contract.md`.

---

## 2. Compile results — real corpus

| File | Rules | yara-x 1.19.0 | yara-python 4.5.4 |
|---|---|---|---|
| `config/yara_rules/corporate_threats.yar` | 5 | **PASS** (5/5, zero warnings) | PASS (5/5) |

**Compile pass rate: 5/5 (100%). Failure taxonomy: empty.** No feature gaps, no syntax-strictness rejections. (yara-x is stricter than libyara on some legacy syntax — none of it appears in this corpus.)

---

## 3. Compile results — synthetic feature probes

Because operators can mount custom rules via ConfigMap, seven probe files exercised features *beyond* the corpus. These are synthetic — not corpus failures.

| Probe | Feature | yara-x | libyara | Analysis |
|---|---|---|---|---|
| `probe_modules.yar` | `import "pe"/"elf"/"math"/"hash"` | PASS | PASS | yara-x warns `pe.number_of_sections` deprecated (use `pe.sections.len()`) — warning only, still compiles |
| `probe_strings.yar` | `nocase wide ascii fullword xor(range) base64 base64wide` | PASS | PASS | full modifier support |
| `probe_hex.yar` | hex wildcards, jumps `[0-64]`, alternatives | PASS | PASS | |
| `probe_loops.yar` | `for any of`, `for any i in`, `at`, `in (..)`, `filesize`, `uint8()` | PASS | PASS | |
| `probe_included.yar` | `include "..."` | PASS | PASS | works with cwd-relative includes |
| `probe_external.yar` | undeclared external vars | FAIL (E009 unknown identifier) | FAIL (undefined identifier) | **identical behavior** — both engines require externals declared at compile time (`Compiler::define_global` ↔ `yara.compile(externals=)`); not a gap |
| `probe_entrypoint.yar` | legacy `entrypoint` keyword | **FAIL (E017 unsupported)** | PASS | **the one real incompatibility**: yara-x intentionally removed `entrypoint`; rewrite as `pe.entry_point` / `elf.entry_point`. Corpus unaffected. Must be documented for operators supplying custom rules |

---

## 4. Match parity

19 deterministic fixtures (generator in appendix): EICAR (bare 68-byte file — canonical `sha256 275a021b…` — plus embedded-mid-file and lowercase-negative variants), benign text + 1 MiB pseudorandom binary, positive/negative cases for every corpus rule including both regex paths (BTC-address, XMR-address) of `Cryptocurrency_Miner_Strings`, a multi-rule file, and a 64 MiB file with sprinkled needles. No real malware — EICAR and crafted literal strings only.

Comparison: yara-x `Scanner::scan` vs yara-python `rules.match(filepath)` (v1's exact call), diffed per file on (a) the set of matching rule identifiers and (b) the set of matched string identifiers per rule.

**Result: 19/19 fixtures identical — zero diffs at rule level, zero diffs at matched-string level.** Highlights:

| Fixture class | Expected | Both engines |
|---|---|---|
| `eicar.com`, `eicar_embedded.bin` | `EICAR_Test_File` | match, `$eicar` |
| `eicar_lowercase_nomatch.txt` | none (string is case-sensitive) | no match |
| `ps_download.ps1`, `ps_encoded.ps1` / `ps_partial_nomatch.ps1` | PowerShell rule / none | agree |
| `office_macro_shell.doc`, `office_macro_http.doc` / `office_macro_nomatch.doc` | Office-macro rule / none | agree |
| `miner_pool/two/wallet/monero` (incl. both regexes) / `miner_one_nomatch` | miner rule / none | agree |
| `multi_threat.bin` | 3 rules simultaneously | agree |
| `benign_random.bin`, `perf_large.bin` | no false positives beyond planted needles | agree |

---

## 5. Performance sanity (order-of-magnitude only)

64 MiB fixture, full 5-rule corpus, 10 iterations after a warm-up scan, same host (in-container):

| Engine | Throughput |
|---|---|
| yara-x 1.19.0 (`Scanner::scan` on bytes) | **480 MB/s** |
| yara-python 4.5.4 (`rules.match(path)`) | **35 MB/s** |

~13x. Not a rigorous benchmark (different I/O paths — bytes-in-memory vs file path; Python call overhead; a 5-rule corpus whose cost is dominated by the two unanchored regexes, which yara-x handles far better). Conclusion for the spike: **yara-x is not a performance regression; it is a large improvement on this corpus.**

---

## 6. Recommendation

**GO: `yara-x = "=1.19.0"`** for Phase 3 `worker-scanner`.

Rationale:
1. 100% compile + 100% match parity on the real corpus and adversarial fixtures.
2. Pure Rust — no libyara C toolchain in the build, no FFI unsafety in a security-sensitive service (aligns with the v2 Rust-only mandate; the plan already lists yara-x in the target stack).
3. ~13x throughput on the corpus.
4. Actively maintained (monthly releases through June 2026).

Phase 3 implementation notes:
- Pin `yara-x = "=1.19.0"` in `services/worker-scanner`'s crate; `cargo audit`/`deny` as usual. Note it pulls wasmtime/cranelift (rule JIT) — expect a heavier build and binary; build time was fine (~90 s warm cache) and is release-gated anyway.
- Rules loading: glob `*.yar`/`*.yara` in `YARA_RULES_PATH` (dir or single file), one `add_source` per file; **fail loudly** on compile error (fixes the v1 silent no-op defect, §1).
- Match result mapping: `MatchingRule::identifier()` → v1 `rule_name`, `namespace()` → `namespace`, `tags()` → `tags`, `patterns()/matches()` → `matched_strings` — everything the v1 `yara_matches` JSON shape needs is available.
- Operator-facing doc: custom rules using the legacy `entrypoint` keyword must be rewritten to `pe.entry_point`/`elf.entry_point`; external variables require the worker to define them (none are defined today, so any such rule was already broken in v1).

**Fallback plan (not triggered):** if a future operator corpus surfaces a hard yara-x gap (realistically only legacy `entrypoint` or exotic libyara-only module fields), wrap the engine behind a small `trait YaraEngine { compile; scan }` in worker-scanner and add a non-default Cargo feature `libyara-ffi` backed by the `yara` FFI crate (libyara 4.5.x). Do **not** pre-build this abstraction beyond the trait seam — the spike found no need for the second implementation.

---

## Appendix — reproduction

All spike files live in the session scratchpad under `yarax-spike/` (`Cargo.toml`, `src/main.rs` harness with `compile`/`scan`/`bench` subcommands, `gen_fixtures.py`, `ref_scan.py`, `rules/` = copy of the corpus, `probes/`, `fixtures/`, `results/`). `$SCRATCH` = scratchpad root, `$SPIKE=$SCRATCH/yarax-spike`.

```bash
# 0. fixtures (deterministic; EICAR + crafted strings only)
cd $SPIKE && python3 gen_fixtures.py fixtures

# 1. build spike harness (yara-x pinned =1.19.0) in the standard Rust image
docker run --rm -v $SPIKE:/spike -v $SCRATCH/cargo-cache:/usr/local/cargo/registry \
  -v $SCRATCH/target-yarax:/spike-target -e CARGO_TARGET_DIR=/spike-target \
  -w /spike rust:1.97-slim-bookworm cargo build --release

# 2. yara-x: compile corpus + probes, scan fixtures, bench
docker run --rm -v $SPIKE:/spike -v $SCRATCH/target-yarax:/t:ro -w /spike/rules \
  rust:1.97-slim-bookworm /t/release/yarax-spike compile corporate_threats.yar
docker run --rm -v $SPIKE:/spike -v $SCRATCH/target-yarax:/t:ro -w /spike/probes \
  rust:1.97-slim-bookworm /t/release/yarax-spike compile probe_*.yar
docker run --rm -v $SPIKE:/spike -v $SCRATCH/target-yarax:/t:ro -w /spike \
  rust:1.97-slim-bookworm /t/release/yarax-spike scan rules/corporate_threats.yar fixtures \
  > results/yarax-scan.json
docker run --rm -v $SPIKE:/spike -v $SCRATCH/target-yarax:/t:ro -w /spike \
  rust:1.97-slim-bookworm /t/release/yarax-spike bench rules/corporate_threats.yar \
  fixtures/perf_large.bin 10

# 3. libyara reference (v1's exact pin), scan + bench + probe compile
docker run --rm -v $SPIKE:/spike -w /spike python:3.13-slim-bookworm sh -c '
  pip install --quiet --no-cache-dir yara-python==4.5.4 &&
  python3 ref_scan.py scan rules/corporate_threats.yar fixtures > results/libyara-scan.json &&
  python3 ref_scan.py bench rules/corporate_threats.yar fixtures/perf_large.bin 10 &&
  cd probes && for f in *.yar; do python3 ../ref_scan.py compile $f; done'

# 4. diff (rule sets + matched-string sets per fixture)
python3 - <<'PY'
import json
yx = json.load(open("results/yarax-scan.json")); ly = json.load(open("results/libyara-scan.json"))
diffs = [f for f in sorted(set(yx) | set(ly)) if yx.get(f) != ly.get(f)]
print("diffs:", diffs or "none")
PY
```
