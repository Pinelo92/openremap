# Architecture Overview

OpenRemap is a service-oriented toolkit for ECU binary identification, diff-based recipe creation, and guided patching. The CLI, TUI, and API are thin entry points — all logic lives in a shared service layer backed by a pluggable extractor registry.

---

## Entry points

| Entry point | Command / package | What it provides |
|---|---|---|
| **CLI** | `openremap` — Typer app in `cli/main.py` | 8 commands (`identify`, `scan`, `cook`, `tune`, `validate`, `families`, `workflow`, `commands`) |
| **TUI** | `openremap-tui` — Textual app in `tui/app.py` | 7 interactive panels covering the same operations |
| **API** | FastAPI server in `server/` | HTTP interface (separate package, not covered here) |

All three entry points call the same service layer — no business logic lives in the interface code.

---

## Pipeline

### Identify flow

```
Binary file (.bin / .ori)
        │
        ▼
  ┌─────────────┐
  │  identifier  │  ← iterates extractor registry
  │  .py         │
  └──────┬───────┘
         │  identity dict
         ▼
  ┌─────────────┐     ┌──────────────┐
  │  confidence  │     │  map_hunter   │
  │  .py         │◄────│  .py          │  (optional map count)
  └──────┬───────┘     └──────────────┘
         │  ConfidenceResult
         ▼
    CLI / TUI output
```

### Tune flow

```
Binary A + Binary B
        │
        ▼
  ┌─────────────────┐
  │  recipe_builder  │  → .remap recipe (JSON)
  │  .py             │
  └──────────────────┘

Target binary + Recipe
        │
        ▼
  ┌──────────────────┐
  │  validate_strict  │  Phase 1: pre-flight
  └────────┬─────────┘
           │ all pass?
           ▼
  ┌──────────────┐
  │   patcher     │  Phase 2: apply
  └────────┬─────┘
           │
           ▼
  ┌───────────────────┐
  │  validate_patched  │  Phase 3: verify
  └───────────────────┘
```

---

## Service layer

All services live in `tuning/services/`.

| Service | What it does |
|---|---|
| `identifier.py` | `identify_ecu()` — runs a binary through all registered extractors, returns the first match with a full identity dict |
| `confidence.py` | `score_identity()` — scores the identity dict → tier, signals, warnings |
| `recipe_builder.py` | `ECUDiffAnalyzer` — byte-level diff of two binaries → `.remap` recipe JSON |
| `patcher.py` | `ECUPatcher` — applies a recipe to a target binary with anchor search (±2 KB) |
| `validate_strict.py` | Pre-patch validation — checks every instruction's `ob` at its exact offset |
| `validate_exists.py` | Diagnostic — searches for `ob` bytes anywhere in the binary (EXACT / SHIFTED / MISSING) |
| `validate_patched.py` | Post-patch validation — confirms `mb` bytes are present at expected offsets |
| `map_hunter.py` | Heuristic map-location discovery — finds calibration map axes in the binary |

---

## Extractor registry

### How detection works

Extractors live in `tuning/manufacturers/`, organised by manufacturer and ECU family:

```
tuning/manufacturers/
├── base.py                  ← BaseManufacturerExtractor (ABC)
├── bosch/
│   ├── __init__.py          ← registers 18 extractors in priority order
│   ├── edc17/
│   │   ├── extractor.py     ← EDC17Extractor class
│   │   └── patterns.py      ← regex patterns + regions
│   └── …
├── siemens/                 ← 6 extractors
├── delphi/                  ← 2 extractors
└── marelli/                 ← 4 extractors
```

30 extractors across 4 manufacturers. Each manufacturer's `__init__.py` registers its extractors in priority order (most specific first).

### The extractor contract

Every extractor subclasses `BaseManufacturerExtractor` and must implement:

- **`can_handle(data: bytes) -> bool`** — detection cascade: size gate → magic bytes → exclusion checks.
- **`extract(data: bytes) -> dict`** — identity extraction: SW version, HW number, family, variant, cal ID, match key.
- **Class attributes:** `manufacturer`, `detection_strength`, `match_key_fallback_field`.

### Priority system

`identifier.py` iterates the registry in registration order. The first extractor whose `can_handle(data)` returns `True` wins — its `extract(data)` result becomes the identity dict. Extractors are registered most-specific-first so that, for example, an EDC17C46 extractor is tried before a generic EDC17 extractor.

---

## Data flow

### Identify (`openremap identify`)

1. Binary loaded into memory
2. `identify_ecu()` iterates registered extractors
3. Each extractor's `can_handle(data)` checks size, magic bytes, exclusion patterns
4. First match runs `extract(data)` → identity dict (manufacturer, family, variant, SW, HW, cal_id, match_key, detection_evidence)
5. `score_identity()` scores the result → `ConfidenceResult` (score, tier, signals, warnings)
6. CLI / TUI renders the output

### Cook (`openremap cook`)

1. Two binaries loaded (stock + tuned)
2. `ECUDiffAnalyzer` diffs them byte-by-byte
3. Produces a `.remap` recipe — JSON with `ob` / `mb` instruction pairs and metadata

### Tune (`openremap tune`)

1. Target binary + `.remap` recipe loaded
2. **Phase 1 — pre-flight:** `validate_strict` checks every instruction's `ob` at exact offset
3. **Phase 2 — apply:** `ECUPatcher` writes `mb` bytes, using anchor search (±2 KB) when offsets drift
4. **Phase 3 — verify:** `validate_patched` confirms all `mb` bytes landed correctly

### Data model

Pydantic schemas in `tuning/schemas/`: `ECUIdentitySchema`, `InstructionSchema`, `RecipeSchema`.

---

## See also

- [Confidence scoring](confidence.md) — how tiers, signals, and warnings are computed
- [Recipe format](recipe-format.md) — the `.remap` file spec

---

← [Back to docs](README.md)