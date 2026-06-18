# sentinel-devlog

A terminal devlog viewer for Sentinel test sessions. Read-only consumer of the
`sentinel_*_results.json` files that `tests/harness.py` writes — it does **not**
require sentinel-core to be running and makes no changes to anything.

Runs alongside `sentinel-ui` (the live ratatui monitor): that window shows
agents in flight, this one shows session history and *why* each signal fired —
drilling down to the exact agent output (the **trigger output**) that tripped
each detector.

## Install & run

```bash
cd ~/Projects/sentinel/sentinel-devlog
npm install
node index.js

# or, after `npm link`:
sentinel-devlog
```

By default it reads `~/Projects/sentinel`. Point it elsewhere with:

```bash
node index.js --dir /path/to/results
```

## Data sources

- `sentinel_test_results.json` — adversarial run (the default set)
- `sentinel_neutral_results.json` — neutral run, loaded if present

Both sets are sorted newest-first by timestamp. Press `N` to toggle between
them when both exist. A non-fire on an adversarial run is a **MISSED**
detection; a non-fire on a neutral run is a **CLEAN** true negative.

## Screens & keys

**Main (suite list)** — one session, navigate sessions with arrows:

| Key | Action |
|---|---|
| `←/H` `→/L` | Previous / next session |
| `↑/K` `↓/J` | Move suite selection |
| `Enter` | Open suite detail |
| `N` | Toggle adversarial / neutral run |
| `/` | Search detectors, signals, responses |
| `E` | Export menu |
| `Q` | Quit |

**Detail (per suite)** — every turn, with the trigger output highlighted:

| Key | Action |
|---|---|
| `Esc/B` | Back |
| `↑/K` `↓/J` `PgUp/PgDn` | Scroll |
| `A` | Copy the trigger output's audit hash to the clipboard |
| `E` | Export current session |
| `Q` | Quit |

## Export

`E` opens an export menu:

1. **Markdown** → `devlogs/sentinel-devlog-YYYY-MM-DD-HH-MM.md` — session
   summary, every suite's status/score/action, and the trigger output for
   each fired suite. Human-readable and committable.
2. **PDF** → same name, `.pdf`. Requires the optional `md-to-pdf` dependency.
3. **Print** → sends the Markdown to the default printer via `lpr`.

`devlogs/` is gitignored — these are generated artifacts.
