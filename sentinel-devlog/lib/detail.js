/**
 * detail.js — per-suite detail view. Renders every turn with its prompt and
 * response, and makes the triggering turn unmistakable: the exact agent output
 * that tripped the detector is shown as the TRIGGER OUTPUT block. Model text
 * is escaped so stray braces can't be read as blessed tags.
 */
'use strict';

const blessed = require('blessed');
const {
  culpritTurn,
  tierLabel,
  formatTimestamp,
} = require('./loader');

const esc = (s) => blessed.escape(String(s == null ? '' : s));
const RULE = '─'.repeat(66);

function detailHeader(suite, session, kind) {
  const kindTag = kind === 'neutral' ? '{cyan-fg}NEUTRAL{/cyan-fg}' : '{magenta-fg}ADVERSARIAL{/magenta-fg}';
  return [
    `{bold}SENTINEL — ${esc(suite.detector)}{/bold}   ${kindTag}`,
    `Session: ${formatTimestamp(session.timestamp)}  |  Model: {bold}${esc(session.model || '?')}{/bold}`,
  ].join('\n');
}

function eventBlock(ev, highlight) {
  const colour = tierLabel(ev.action) === 'hard' ? 'red' : 'yellow';
  const lines = [
    `  Signal:   {${colour}-fg}{bold}${esc(ev.signal)}{/bold}{/${colour}-fg}`,
    `  Score:    ${(ev.score != null ? ev.score : 0).toFixed(3)}`,
    `  Action:   {${colour}-fg}${esc(ev.action)}{/${colour}-fg}`,
  ];
  if (ev.audit_hash) lines.push(`  Audit:    {gray-fg}${esc(ev.audit_hash)}{/gray-fg}`);
  else lines.push(`  Audit:    {gray-fg}(none — observe-only event){/gray-fg}`);
  return lines.join('\n');
}

/**
 * The scrollable body for a suite's detail view. `term` (optional) highlights
 * matching substrings in prompts/responses.
 */
function suiteDetailBody(suite, kind, term) {
  if (!suite || !Array.isArray(suite.turns) || suite.turns.length === 0) {
    return '{red-fg}(no turns recorded for this suite){/red-fg}';
  }
  const culprit = culpritTurn(suite);
  const blocks = [];

  for (const turn of suite.turns) {
    const fired = Array.isArray(turn.sentinel_events) && turn.sentinel_events.length > 0;
    const out = [];
    out.push(`{gray-fg}${RULE}{/gray-fg}`);
    if (fired) {
      out.push(`{red-fg}{bold}Turn ${turn.turn}  —  *** SIGNAL FIRED ***{/bold}{/red-fg}`);
    } else {
      out.push(`{bold}Turn ${turn.turn}{/bold}  {gray-fg}—  no signal{/gray-fg}`);
    }
    out.push(`{cyan-fg}Prompt:{/cyan-fg}   ${highlight(esc(turn.prompt), term)}`);

    if (fired) {
      for (const ev of turn.sentinel_events) out.push(eventBlock(ev));
      out.push('');
      out.push('{red-fg}{bold}TRIGGER OUTPUT:{/bold}{/red-fg}');
      out.push(`{yellow-fg}${highlight(esc(turn.response), term)}{/yellow-fg}`);
    } else {
      out.push(`{cyan-fg}Response:{/cyan-fg} ${highlight(esc(turn.response), term)}`);
    }
    out.push(
      `{gray-fg}Words: ${turn.word_count != null ? turn.word_count : '?'}  |  Elapsed: ${
        turn.elapsed_ms != null ? Math.round(turn.elapsed_ms) + 'ms' : '?'
      }{/gray-fg}`
    );
    blocks.push(out.join('\n'));
  }

  if (!culprit) {
    blocks.unshift('{yellow-fg}This suite did not fire — no trigger output.{/yellow-fg}\n');
  }
  return blocks.join('\n\n');
}

/** Case-insensitively wrap occurrences of `term` in an inverse tag. */
function highlight(text, term) {
  if (!term) return text;
  const needle = term.toLowerCase();
  const hay = text.toLowerCase();
  if (!hay.includes(needle)) return text;
  let result = '';
  let i = 0;
  while (i < text.length) {
    const at = hay.indexOf(needle, i);
    if (at === -1) {
      result += text.slice(i);
      break;
    }
    result += text.slice(i, at) + `{inverse}${text.slice(at, at + term.length)}{/inverse}`;
    i = at + term.length;
  }
  return result;
}

/** The audit hash to copy with [A] — the culprit's first event hash. */
function primaryAuditHash(suite) {
  const t = culpritTurn(suite);
  if (!t) return null;
  const ev = (t.sentinel_events || []).find((e) => e.audit_hash);
  return ev ? ev.audit_hash : null;
}

module.exports = { detailHeader, suiteDetailBody, highlight, primaryAuditHash };
