/**
 * loader.js — reads and parses sentinel_*_results.json files and exposes the
 * pure classification helpers the views depend on. No blessed, no I/O beyond
 * the initial directory read so the helpers stay trivially testable.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_DIR = path.join(os.homedir(), 'Projects', 'sentinel');

// sentinel_test_results.json, sentinel_neutral_results.json, and any other
// sentinel_<name>_results.json the harness might write.
const RESULT_RE = /^sentinel_.*results\.json$/;

function isNeutral(file) {
  return path.basename(file) === 'sentinel_neutral_results.json';
}

function isResultFile(file) {
  return RESULT_RE.test(path.basename(file));
}

function parseFile(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  data._file = path.basename(file);
  data._kind = isNeutral(file) ? 'neutral' : 'adversarial';
  return data;
}

/**
 * Load every result file in `dir`, split into adversarial and neutral sets,
 * each sorted newest-first by timestamp. Malformed files are skipped (their
 * names collected in `errors`) rather than crashing the viewer.
 */
function loadSessions(dir = DEFAULT_DIR) {
  const out = { adversarial: [], neutral: [], dir, errors: [] };
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (e) {
    out.errors.push(`cannot read ${dir}: ${e.message}`);
    return out;
  }
  for (const name of entries) {
    if (!isResultFile(name)) continue;
    const full = path.join(dir, name);
    let session;
    try {
      session = parseFile(full);
    } catch (e) {
      out.errors.push(`${name}: ${e.message}`);
      continue;
    }
    (session._kind === 'neutral' ? out.neutral : out.adversarial).push(session);
  }
  const newestFirst = (a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || ''));
  out.adversarial.sort(newestFirst);
  out.neutral.sort(newestFirst);
  return out;
}

// ── Pure classification helpers ──────────────────────────────────────────────

/** First turn whose sentinel_events fired — the culprit turn (or null). */
function culpritTurn(suite) {
  if (!suite || !Array.isArray(suite.turns)) return null;
  return suite.turns.find((t) => Array.isArray(t.sentinel_events) && t.sentinel_events.length > 0) || null;
}

/** Flat list of every degradation event across all turns of a suite. */
function suiteEvents(suite) {
  const events = [];
  for (const t of (suite && suite.turns) || []) {
    for (const e of t.sentinel_events || []) events.push(e);
  }
  return events;
}

/**
 * Status from the suite's perspective. A non-fire is a *true negative* (CLEAN)
 * on a neutral run but a *missed detection* (MISSED) on an adversarial run.
 */
function suiteStatus(suite, kind) {
  if (suite && suite.fired) return 'FIRED';
  return kind === 'neutral' ? 'CLEAN' : 'MISSED';
}

const ACTION_RANK = { no_action: 0, soft_pause: 1, paused: 1, write_suspended: 2, terminated: 3 };

/** The most severe action taken across the suite's events (or null). */
function strongestAction(suite) {
  const actions = suiteEvents(suite).map((e) => e.action).filter(Boolean);
  if (!actions.length) return null;
  return actions.sort((a, b) => (ACTION_RANK[b] || 0) - (ACTION_RANK[a] || 0))[0];
}

/** Coarse severity tier used for colour coding. */
function tierLabel(action) {
  if (action === 'terminated') return 'hard';
  if (action === 'soft_pause' || action === 'paused' || action === 'write_suspended') return 'soft';
  return 'observe';
}

/**
 * Human-readable progression of the consequential actions in order, e.g.
 * "paused → terminated". no_action events are dropped; consecutive dupes
 * collapse. Returns "observed" if nothing beyond no_action ever happened.
 */
function actionProgression(suite) {
  const pretty = { soft_pause: 'paused', paused: 'paused', write_suspended: 'write-suspended', terminated: 'terminated' };
  const steps = [];
  for (const e of suiteEvents(suite)) {
    const p = pretty[e.action];
    if (!p) continue;
    if (steps[steps.length - 1] !== p) steps.push(p);
  }
  return steps.length ? steps.join(' → ') : 'observed';
}

/** "2026-06-17 04:40:51" from an ISO-ish timestamp; falls back to the raw value. */
function formatTimestamp(ts) {
  if (!ts) return '—';
  const m = String(ts).match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]}` : String(ts);
}

module.exports = {
  DEFAULT_DIR,
  loadSessions,
  parseFile,
  isNeutral,
  isResultFile,
  culpritTurn,
  suiteEvents,
  suiteStatus,
  strongestAction,
  tierLabel,
  actionProgression,
  formatTimestamp,
};
