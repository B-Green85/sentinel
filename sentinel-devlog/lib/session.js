/**
 * session.js — header rendering for the main view. The main view shows one
 * session at a time (navigated with ←/→) with its suite list below; this
 * module owns the three-line summary header at the top.
 */
'use strict';

const { formatTimestamp } = require('./loader');

const TITLE = 'SENTINEL — Devlog';

/**
 * The header block for the main view. Returns blessed-tagged text:
 *   line 1: title + run kind + timestamp
 *   line 2: session N of M | model
 *   line 3: suites | fired | missed
 */
function sessionHeader(session, index, total, kind) {
  if (!session) {
    return `{bold}${TITLE}{/bold}\n{red-fg}No ${kind} sessions found.{/red-fg}\n `;
  }
  const s = session.summary || {};
  const kindTag = kind === 'neutral' ? '{cyan-fg}NEUTRAL{/cyan-fg}' : '{magenta-fg}ADVERSARIAL{/magenta-fg}';
  const fired = `{red-fg}Fired: ${s.fired != null ? s.fired : '?'}{/red-fg}`;
  const missed = `{yellow-fg}Missed: ${s.missed != null ? s.missed : '?'}{/yellow-fg}`;
  return [
    `{bold}${TITLE}{/bold}   ${kindTag}{|}${formatTimestamp(session.timestamp)}`,
    `Session ${index + 1} of ${total}  |  Model: {bold}${session.model || '?'}{/bold}  |  Agent: ${session.agent_id || '?'}`,
    `Suites: ${s.total != null ? s.total : '?'}  |  ${fired}  |  ${missed}`,
  ].join('\n');
}

module.exports = { TITLE, sessionHeader };
