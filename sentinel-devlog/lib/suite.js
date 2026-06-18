/**
 * suite.js — renders the suite list shown in the main view. Each suite is a
 * two-line block (status row + tier/action row); the selected suite is marked
 * and highlighted. Pure string rendering with blessed tags — the interactive
 * layer in index.js owns selection state and scrolling.
 */
'use strict';

const {
  culpritTurn,
  suiteStatus,
  strongestAction,
  tierLabel,
  actionProgression,
} = require('./loader');

const LINES_PER_SUITE = 3; // status row, tier row, blank spacer

function pad(str, width) {
  str = String(str);
  return str.length >= width ? str.slice(0, width) : str + ' '.repeat(width - str.length);
}

function statusBadge(status) {
  const colour =
    status === 'FIRED' ? 'red' : status === 'CLEAN' ? 'green' : 'yellow';
  return `{${colour}-fg}{bold}[${pad(status, 6)}]{/bold}{/${colour}-fg}`;
}

function severityMarker(status, action) {
  if (status !== 'FIRED') return ' ';
  const tier = tierLabel(action);
  if (tier === 'hard') return '{red-fg}●{/red-fg}';
  if (tier === 'soft') return '{yellow-fg}◐{/yellow-fg}';
  return '{yellow-fg}○{/yellow-fg}';
}

/** The colour used for the detector name and tier line, by status/severity. */
function rowColour(status, action) {
  if (status === 'CLEAN') return 'green';
  if (status === 'MISSED') return 'red';
  return tierLabel(action) === 'hard' ? 'red' : 'yellow';
}

/**
 * Build the full suite-list body as a tagged string.
 *   opts.selIndex — index of the selected suite (highlighted)
 *   opts.matches  — optional Set of suite indices matching an active search
 */
function suiteListBody(session, kind, opts = {}) {
  const { selIndex = 0, matches = null } = opts;
  if (!session || !Array.isArray(session.suites) || session.suites.length === 0) {
    return '{red-fg}(this session has no suites){/red-fg}';
  }
  const lines = [];
  session.suites.forEach((suite, i) => {
    const status = suiteStatus(suite, kind);
    const action = strongestAction(suite);
    const colour = rowColour(status, action);
    const selected = i === selIndex;
    const isMatch = matches && matches.has(i);

    const culprit = culpritTurn(suite);
    const turnCol = suite.fired
      ? `turn ${suite.first_fire_turn != null ? suite.first_fire_turn : (culprit ? culprit.turn : '?')}`
      : '—';
    const score = (suite.final_score != null ? suite.final_score : 0).toFixed(2);

    const marker = selected ? '{bold}▶{/bold}' : isMatch ? '{cyan-fg}·{/cyan-fg}' : ' ';
    const name = `{${colour}-fg}${pad(suite.detector, 36)}{/${colour}-fg}`;

    let row1 =
      `${marker} ${statusBadge(status)}  ${name}  ${pad(turnCol, 8)}  score ${score}  ${severityMarker(status, action)}`;

    let tierText;
    if (status === 'FIRED') {
      tierText = `${tierLabel(action)} — ${actionProgression(suite)}`;
    } else if (status === 'CLEAN') {
      tierText = 'true negative';
    } else {
      tierText = 'MISSED — detector did not fire';
    }
    let row2 = `    {${colour}-fg}${tierText}{/${colour}-fg}`;

    if (selected) {
      row1 = `{inverse}${row1}{/inverse}`;
      row2 = `{inverse}${row2}{/inverse}`;
    }
    lines.push(row1, row2, '');
  });
  return lines.join('\n');
}

module.exports = { LINES_PER_SUITE, suiteListBody, statusBadge, rowColour };
