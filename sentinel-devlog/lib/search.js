/**
 * search.js — pure search helpers used by the `/` overlay. Matching spans
 * detector names, signal types, and response text, case-insensitively.
 */
'use strict';

function matchSuite(suite, term) {
  if (!term) return false;
  const needle = term.toLowerCase();
  if (String(suite.detector || '').toLowerCase().includes(needle)) return true;
  for (const turn of suite.turns || []) {
    if (String(turn.response || '').toLowerCase().includes(needle)) return true;
    if (String(turn.prompt || '').toLowerCase().includes(needle)) return true;
    for (const ev of turn.sentinel_events || []) {
      if (String(ev.signal || '').toLowerCase().includes(needle)) return true;
    }
  }
  return false;
}

/** Set of suite indices in a session that match `term`. */
function matchingSuiteIndices(session, term) {
  const hits = new Set();
  if (!session || !term) return hits;
  (session.suites || []).forEach((suite, i) => {
    if (matchSuite(suite, term)) hits.add(i);
  });
  return hits;
}

module.exports = { matchSuite, matchingSuiteIndices };
