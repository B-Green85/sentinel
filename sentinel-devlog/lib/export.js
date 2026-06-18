/**
 * export.js — render a session to committable Markdown, and from there to PDF
 * (via the optional md-to-pdf dependency) or the system printer (via lpr).
 * Generated files land in <dir>/devlogs/ which is gitignored.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const {
  culpritTurn,
  suiteStatus,
  strongestAction,
  tierLabel,
  actionProgression,
  formatTimestamp,
} = require('./loader');

function fileStamp(session) {
  // Prefer the run's own timestamp so the filename is deterministic.
  const m = String(session.timestamp || '').match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  return new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-');
}

// Exports default to the viewer's own devlogs/ (gitignored). `dir` overrides
// the base directory; the devlogs/ leaf is always appended.
function exportPath(session, ext, dir) {
  const base = dir || path.join(__dirname, '..');
  const out = path.join(base, 'devlogs');
  return path.join(out, `sentinel-devlog-${fileStamp(session)}.${ext}`);
}

/** Build a human-readable, committable Markdown report for one session. */
function buildMarkdown(session, kind) {
  const s = session.summary || {};
  const lines = [];
  lines.push(`# Sentinel Devlog — ${formatTimestamp(session.timestamp)}`);
  lines.push('');
  lines.push(`- **Run kind:** ${kind}`);
  lines.push(`- **Model:** ${session.model || '?'}`);
  lines.push(`- **Agent:** ${session.agent_id || '?'}`);
  lines.push(`- **Suites:** ${s.total != null ? s.total : '?'}  |  **Fired:** ${s.fired != null ? s.fired : '?'}  |  **Missed:** ${s.missed != null ? s.missed : '?'}`);
  lines.push('');
  lines.push('## Suites');
  lines.push('');
  lines.push('| Detector | Status | Turn | Score | Action |');
  lines.push('|---|---|---|---|---|');
  for (const suite of session.suites || []) {
    const status = suiteStatus(suite, kind);
    const action = strongestAction(suite);
    const turn = suite.fired ? (suite.first_fire_turn != null ? suite.first_fire_turn : '?') : '—';
    const score = (suite.final_score != null ? suite.final_score : 0).toFixed(2);
    const actionText = status === 'FIRED' ? `${tierLabel(action)} — ${actionProgression(suite)}` : (status === 'CLEAN' ? 'true negative' : 'not fired');
    lines.push(`| ${suite.detector} | ${status} | ${turn} | ${score} | ${actionText} |`);
  }
  lines.push('');

  lines.push('## Culprit responses');
  lines.push('');
  let any = false;
  for (const suite of session.suites || []) {
    if (!suite.fired) continue;
    const turn = culpritTurn(suite);
    if (!turn) continue;
    any = true;
    lines.push(`### ${suite.detector}`);
    lines.push('');
    const ev = (turn.sentinel_events || [])[0] || {};
    lines.push(`- Turn ${turn.turn} · signal \`${ev.signal}\` · score ${(ev.score != null ? ev.score : 0).toFixed(3)} · action **${ev.action}**`);
    if (ev.audit_hash) lines.push(`- Audit: \`${ev.audit_hash}\``);
    lines.push('');
    lines.push('**Prompt:**');
    lines.push('');
    lines.push('> ' + String(turn.prompt || '').replace(/\n/g, '\n> '));
    lines.push('');
    lines.push('**Culprit response:**');
    lines.push('');
    lines.push('```');
    lines.push(String(turn.response || '').trim());
    lines.push('```');
    lines.push('');
  }
  if (!any) {
    lines.push('_No suites fired in this session._');
    lines.push('');
  }
  return lines.join('\n');
}

function ensureDir(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
}

/** Write Markdown to devlogs/. Returns the path written. */
function exportMarkdown(session, kind, dir) {
  const out = exportPath(session, 'md', dir);
  ensureDir(out);
  fs.writeFileSync(out, buildMarkdown(session, kind), 'utf8');
  return out;
}

/**
 * Render the Markdown to PDF via md-to-pdf. The dependency is optional, so the
 * caller gets a clear rejection if it isn't installed.
 */
async function exportPdf(session, kind, dir) {
  let mdToPdf;
  try {
    ({ mdToPdf } = require('md-to-pdf'));
  } catch (e) {
    throw new Error('md-to-pdf is not installed — run `npm install md-to-pdf`');
  }
  const md = buildMarkdown(session, kind);
  const out = exportPath(session, 'pdf', dir);
  ensureDir(out);
  const pdf = await mdToPdf({ content: md }, { dest: out });
  return (pdf && pdf.filename) || out;
}

/**
 * Send the Markdown to the default printer via lpr as plain monospace text.
 * Resolves on a zero exit code, rejects otherwise.
 */
function printMarkdown(session, kind) {
  return new Promise((resolve, reject) => {
    const md = buildMarkdown(session, kind);
    let child;
    try {
      child = spawn('lpr', [], { stdio: ['pipe', 'ignore', 'pipe'] });
    } catch (e) {
      reject(new Error(`could not launch lpr: ${e.message}`));
      return;
    }
    let stderr = '';
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', (e) => reject(new Error(`lpr failed: ${e.message}`)));
    child.on('close', (code) => {
      if (code === 0) resolve(true);
      else reject(new Error(`lpr exited ${code}${stderr ? ': ' + stderr.trim() : ''}`));
    });
    child.stdin.write(md);
    child.stdin.end();
  });
}

module.exports = { buildMarkdown, exportMarkdown, exportPdf, printMarkdown, exportPath };
