# Rules Documentation Design

**Date:** 2026-06-25
**Status:** Approved
**Output:** `docs/rules.md`

## Goal

Write a single reference document (`docs/rules.md`) covering the `rules.yaml` schema,
evaluation semantics, all known reason codes, and deployment recipes for the four
main node archetypes. Audience: operators and developers.

## Document structure

```
# Rules Reference

## Overview
## File location and loading
## Evaluation semantics
  - AND logic, first-match wins
  - Hot-reload
  - Legacy mode (no rules file)
## Field reference
  (one table: name, reason, min_score, min_corroboration, anchored_only,
   min_burst, burst_window, action)
## Reason code catalogue
  (table: code | source adapter | meaning)
## Deployment recipes
  - Sensor / honeypot node
  - Mail server (Mailcow)
  - Web server (WordPress)
  - General-purpose / solo
```

## Prose sections

**Overview:** `rules.yaml` is a list of named rules that determine what FederLoom
does when an IP is observed. Rules replace legacy score-only threshold mode and
give operators fine-grained control: block on high-confidence single events,
require corroboration from multiple peers, or trigger on burst activity within
a time window.

**File location and loading:** `reputation.rules_file` in `config.yaml` points to
it; if unset, auto-discovered at `<store.dir>/rules.yaml`; if absent, legacy mode
(block when score ≥ `block_threshold`). Hot-reload: daemon watches mtime/size and
reloads automatically — no restart required. On parse error after a successful
load, last-good ruleset is kept and a warning is logged.

**Evaluation semantics:**
- Top-to-bottom; first match wins.
- All conditions ANDed — omitting a field skips that check.
- Actions: `block`, `watch`, `ignore`.
- A rule with no conditions always matches (useful as catch-all).
- Misconfigured rules (unknown action, `min_burst` without `burst_window`) dropped
  at load with a log warning.

## Field reference format

One table with columns: Field | Type | Required | Description.
Duration fields note Go notation (`10m`, `1h`). Wildcard pattern noted for `reason`.

## Reason code catalogue

Table: Reason code | Source adapter | Meaning.
Covers all codes found across the five deploy examples and the ingest adapters.

## Deployment recipes format

Four annotated YAML snippets — one subsection each. Comments in the YAML explain
the ordering rationale (why high-confidence rules come first, why a catch-all
belongs last).

## Source of truth

Field names and validation rules are derived from `internal/rules/rule.go`.
Known reason codes are derived from adapter source files under `internal/ingest/`
and the deploy example files under `deploy/`.
