#!/usr/bin/env node
/**
 * sentinel-devlog — terminal devlog viewer for Sentinel test sessions.
 *
 * Read-only consumer of sentinel_*_results.json. Two screens:
 *   main   — one session's 12 suites, navigate sessions with ←/→
 *   detail — every turn of a suite, with the TRIGGER OUTPUT highlighted
 *
 * Layout follows the blessed pager pattern: a header box, a scrolling body,
 * and a footer of key hints. All rendering is delegated to the pure helpers in
 * lib/; this file owns state, widgets, and key handling only.
 */
'use strict';

const path = require('path');
const { spawn } = require('child_process');
const blessed = require('blessed');

const loader = require('./lib/loader');
const { sessionHeader } = require('./lib/session');
const { suiteListBody, LINES_PER_SUITE } = require('./lib/suite');
const { detailHeader, suiteDetailBody, primaryAuditHash } = require('./lib/detail');
const { matchingSuiteIndices } = require('./lib/search');
const { exportMarkdown, exportPdf, printMarkdown } = require('./lib/export');

// ── Args & data ──────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const out = { dir: loader.DEFAULT_DIR };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dir' && argv[i + 1]) out.dir = argv[++i];
    else if (argv[i] === '--help' || argv[i] === '-h') out.help = true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(
    'sentinel-devlog [--dir <path>]\n\n' +
      'Reads sentinel_*_results.json from <path> (default ~/Projects/sentinel)\n' +
      'and displays session history with trigger-output drill-down.\n'
  );
  process.exit(0);
}

const data = loader.loadSessions(args.dir);

const FOOTER_MAIN =
  '{cyan-fg}[←/H]{/} Prev session  {cyan-fg}[→/L]{/} Next session  {cyan-fg}[↑/K]{/} Up  {cyan-fg}[↓/J]{/} Down\n' +
  '{cyan-fg}[Enter]{/} Detail  {cyan-fg}[N]{/} {NTOGGLE}  {cyan-fg}[/]{/} Search  {cyan-fg}[E]{/} Export  {cyan-fg}[Q]{/} Quit';
const FOOTER_DETAIL =
  '{cyan-fg}[Esc/B]{/} Back  {cyan-fg}[↑/K]{/} Up  {cyan-fg}[↓/J]{/} Down  {cyan-fg}[PgUp/PgDn]{/} Page\n' +
  '{cyan-fg}[A]{/} Audit hash  {cyan-fg}[/]{/} Search  {cyan-fg}[E]{/} Export  {cyan-fg}[Q]{/} Quit';

const state = {
  kind: data.adversarial.length ? 'adversarial' : 'neutral',
  sessionIndex: 0,
  suiteIndex: 0,
  view: 'main', // 'main' | 'detail'
  searchTerm: '',
  matches: null, // Set<number> | null
  overlay: null, // 'search' | 'export' | 'popup' | null
};

const sessionsOf = (kind) => data[kind] || [];
const currentSessions = () => sessionsOf(state.kind);
const currentSession = () => currentSessions()[state.sessionIndex] || null;
const currentSuite = () => {
  const s = currentSession();
  return s && s.suites ? s.suites[state.suiteIndex] : null;
};
const otherKind = () => (state.kind === 'adversarial' ? 'neutral' : 'adversarial');

// ── Widgets ──────────────────────────────────────────────────────────────────
const screen = blessed.screen({
  smartCSR: true,
  title: 'sentinel-devlog',
  fullUnicode: true,
  autoPadding: true,
});

const header = blessed.box({
  parent: screen,
  top: 0,
  left: 0,
  right: 0,
  height: 4,
  tags: true,
  padding: { left: 1, right: 1 },
  style: { fg: 'white' },
});

const rule = blessed.line({ parent: screen, orientation: 'horizontal', top: 4, left: 0, right: 0, style: { fg: 'gray' } });

const body = blessed.box({
  parent: screen,
  top: 5,
  left: 0,
  right: 0,
  bottom: 4,
  tags: true,
  scrollable: true,
  alwaysScroll: true,
  keys: false,
  padding: { left: 1, right: 1 },
  scrollbar: { ch: ' ', style: { bg: 'gray' } },
});

const detail = blessed.box({
  parent: screen,
  top: 5,
  left: 0,
  right: 0,
  bottom: 4,
  tags: true,
  scrollable: true,
  alwaysScroll: true,
  keys: false,
  hidden: true,
  padding: { left: 1, right: 1 },
  scrollbar: { ch: ' ', style: { bg: 'gray' } },
});

const footerRule = blessed.line({ parent: screen, orientation: 'horizontal', bottom: 3, left: 0, right: 0, style: { fg: 'gray' } });

const footer = blessed.box({
  parent: screen,
  bottom: 0,
  left: 0,
  right: 0,
  height: 3,
  tags: true,
  padding: { left: 1, right: 1 },
  style: { fg: 'white' },
});

// Search input (hidden until invoked)
const searchBox = blessed.textbox({
  parent: screen,
  bottom: 0,
  left: 0,
  right: 0,
  height: 1,
  hidden: true,
  inputOnFocus: true,
  style: { fg: 'black', bg: 'cyan' },
});

// Export menu (hidden until invoked)
const exportMenu = blessed.list({
  parent: screen,
  hidden: true,
  top: 'center',
  left: 'center',
  width: 40,
  height: 8,
  label: ' Export ',
  border: 'line',
  tags: true,
  keys: true,
  vi: true,
  style: {
    selected: { bg: 'cyan', fg: 'black' },
    border: { fg: 'cyan' },
    label: { fg: 'cyan' },
  },
  items: ['Markdown (.md)', 'PDF (.pdf)', 'Print (lpr)', 'Cancel'],
});

// Popup message box (hidden until invoked)
const popup = blessed.box({
  parent: screen,
  hidden: true,
  top: 'center',
  left: 'center',
  width: '80%',
  height: 'shrink',
  border: 'line',
  tags: true,
  padding: 1,
  style: { border: { fg: 'cyan' } },
});

// ── Rendering ────────────────────────────────────────────────────────────────
function clampSuiteIndex() {
  const s = currentSession();
  const n = s && s.suites ? s.suites.length : 0;
  if (n === 0) state.suiteIndex = 0;
  else state.suiteIndex = Math.max(0, Math.min(state.suiteIndex, n - 1));
}

function render() {
  if (state.view === 'detail') return renderDetail();
  return renderMain();
}

function noData() {
  return data.adversarial.length === 0 && data.neutral.length === 0;
}

function renderMain() {
  detail.hide();
  body.show();

  if (noData()) {
    header.setContent('{bold}SENTINEL — Devlog{/bold}');
    const errs = data.errors.length ? '\n{red-fg}' + data.errors.join('\n') + '{/red-fg}' : '';
    body.setContent(`{red-fg}No sentinel_*_results.json files found in{/red-fg}\n  ${args.dir}${errs}`);
    footer.setContent('{cyan-fg}[Q]{/} Quit');
    screen.render();
    return;
  }

  clampSuiteIndex();
  const sessions = currentSessions();
  const session = currentSession();
  header.setContent(sessionHeader(session, state.sessionIndex, sessions.length, state.kind));

  body.setContent(
    suiteListBody(session, state.kind, { selIndex: state.suiteIndex, matches: state.matches })
  );
  // Keep the selected suite comfortably in view.
  const target = Math.max(0, state.suiteIndex * LINES_PER_SUITE - 2);
  body.setScroll(target);

  const nLabel = otherKind() === 'neutral' ? 'Neutral run' : 'Adversarial run';
  const enabled = sessionsOf(otherKind()).length > 0;
  footer.setContent(
    FOOTER_MAIN.replace('{NTOGGLE}', enabled ? nLabel : '{gray-fg}' + nLabel + ' (none){/gray-fg}')
  );
  screen.render();
}

function renderDetail() {
  body.hide();
  detail.show();
  const suite = currentSuite();
  const session = currentSession();
  if (!suite) {
    state.view = 'main';
    return renderMain();
  }
  header.setContent(detailHeader(suite, session, state.kind));
  detail.setContent(suiteDetailBody(suite, state.kind, state.searchTerm || null));
  footer.setContent(FOOTER_DETAIL);
  screen.render();
}

// ── Overlays ─────────────────────────────────────────────────────────────────
function showPopup(content, title) {
  popup.setLabel(title ? ` ${title} ` : '');
  popup.setContent(content + '\n\n{gray-fg}(press any key to dismiss){/gray-fg}');
  popup.show();
  popup.setFront();
  state.overlay = 'popup';
  popup.focus();
  screen.render();
}

popup.key(['escape', 'enter', 'space', 'q', 'a', 'b'], dismissPopup);
function dismissPopup() {
  if (state.overlay !== 'popup') return;
  popup.hide();
  state.overlay = null;
  restoreFocus();
  render();
}

function openSearch() {
  state.overlay = 'search';
  searchBox.show();
  searchBox.setFront();
  footer.hide();
  footerRule.hide();
  searchBox.setValue('');
  screen.render();
  searchBox.readInput();
}

searchBox.on('submit', (val) => {
  finishSearch(val);
});
searchBox.on('cancel', () => finishSearch(null));

function finishSearch(val) {
  searchBox.hide();
  footer.show();
  footerRule.show();
  state.overlay = null;
  if (val != null && val.trim()) {
    state.searchTerm = val.trim();
    const session = currentSession();
    state.matches = matchingSuiteIndices(session, state.searchTerm);
    const first = [...state.matches].sort((a, b) => a - b)[0];
    if (state.view === 'main' && first != null) state.suiteIndex = first;
    if (state.matches.size === 0) {
      restoreFocus();
      render();
      showPopup(`No matches for "{bold}${blessed.escape(state.searchTerm)}{/bold}".`, 'Search');
      return;
    }
  } else {
    state.searchTerm = '';
    state.matches = null;
  }
  restoreFocus();
  render();
}

function openExportMenu() {
  if (noData()) return;
  state.overlay = 'export';
  exportMenu.select(0);
  exportMenu.show();
  exportMenu.setFront();
  exportMenu.focus();
  screen.render();
}

exportMenu.on('select', (_item, index) => {
  exportMenu.hide();
  state.overlay = null;
  restoreFocus();
  render();
  runExport(index);
});
exportMenu.key(['escape', 'q'], () => {
  exportMenu.hide();
  state.overlay = null;
  restoreFocus();
  render();
});

async function runExport(index) {
  const session = currentSession();
  if (!session) return;
  try {
    if (index === 0) {
      const out = exportMarkdown(session, state.kind);
      showPopup(`Markdown written to:\n{green-fg}${blessed.escape(out)}{/green-fg}`, 'Export');
    } else if (index === 1) {
      showPopup('Generating PDF…', 'Export');
      const out = await exportPdf(session, state.kind);
      showPopup(`PDF written to:\n{green-fg}${blessed.escape(out)}{/green-fg}`, 'Export');
    } else if (index === 2) {
      await printMarkdown(session, state.kind);
      showPopup('Sent to the default printer via {bold}lpr{/bold}.', 'Print');
    }
    // index 3 == Cancel → nothing
  } catch (e) {
    showPopup(`{red-fg}${blessed.escape(e.message)}{/red-fg}`, 'Export failed');
  }
}

function restoreFocus() {
  if (state.view === 'detail') detail.focus();
  else body.focus();
}

// ── Audit hash copy ──────────────────────────────────────────────────────────
function copyAuditHash() {
  const suite = currentSuite();
  const hash = suite && primaryAuditHash(suite);
  if (!hash) {
    showPopup('No audit hash on this suite (the firing event was observe-only).', 'Audit hash');
    return;
  }
  const cmd = process.platform === 'darwin' ? 'pbcopy' : 'xclip';
  const cargs = process.platform === 'darwin' ? [] : ['-selection', 'clipboard'];
  let copied = false;
  try {
    const child = spawn(cmd, cargs, { stdio: ['pipe', 'ignore', 'ignore'] });
    child.on('error', () => {});
    child.stdin.write(hash);
    child.stdin.end();
    copied = true;
  } catch (e) {
    copied = false;
  }
  const note = copied ? '{green-fg}Copied to clipboard.{/green-fg}' : '{yellow-fg}(clipboard unavailable){/yellow-fg}';
  showPopup(`{bold}${blessed.escape(hash)}{/bold}\n\n${note}`, 'Audit hash');
}

// ── Navigation ───────────────────────────────────────────────────────────────
function moveSession(delta) {
  const sessions = currentSessions();
  if (sessions.length === 0) return;
  state.sessionIndex = Math.max(0, Math.min(state.sessionIndex + delta, sessions.length - 1));
  state.suiteIndex = 0;
  if (state.searchTerm) state.matches = matchingSuiteIndices(currentSession(), state.searchTerm);
  render();
}

function moveSuite(delta) {
  const s = currentSession();
  const n = s && s.suites ? s.suites.length : 0;
  if (n === 0) return;
  state.suiteIndex = Math.max(0, Math.min(state.suiteIndex + delta, n - 1));
  render();
}

function toggleKind() {
  const other = otherKind();
  if (sessionsOf(other).length === 0) return;
  state.kind = other;
  state.sessionIndex = 0;
  state.suiteIndex = 0;
  state.matches = state.searchTerm ? matchingSuiteIndices(currentSession(), state.searchTerm) : null;
  render();
}

// ── Key handling ─────────────────────────────────────────────────────────────
function inOverlay() {
  return state.overlay != null;
}

screen.key(['q', 'C-c'], () => {
  if (inOverlay()) return; // overlays own q
  process.exit(0);
});

screen.key('/', () => {
  if (inOverlay()) return;
  openSearch();
});

screen.key('e', () => {
  if (inOverlay()) return;
  openExportMenu();
});

// Main-view keys
screen.key(['left', 'h'], () => {
  if (inOverlay() || state.view !== 'main') return;
  moveSession(-1);
});
screen.key(['right', 'l'], () => {
  if (inOverlay() || state.view !== 'main') return;
  moveSession(1);
});
screen.key(['up', 'k'], () => {
  if (inOverlay()) return;
  if (state.view === 'main') moveSuite(-1);
  else { detail.scroll(-2); screen.render(); }
});
screen.key(['down', 'j'], () => {
  if (inOverlay()) return;
  if (state.view === 'main') moveSuite(1);
  else { detail.scroll(2); screen.render(); }
});
screen.key(['pageup'], () => {
  if (inOverlay()) return;
  if (state.view === 'detail') { detail.scroll(-(detail.height - 2)); screen.render(); }
});
screen.key(['pagedown'], () => {
  if (inOverlay()) return;
  if (state.view === 'detail') { detail.scroll(detail.height - 2); screen.render(); }
});
screen.key(['enter'], () => {
  if (inOverlay() || state.view !== 'main') return;
  if (!currentSuite()) return;
  state.view = 'detail';
  detail.setScroll(0);
  render();
});
screen.key(['escape', 'b'], () => {
  if (inOverlay()) return;
  if (state.view === 'detail') {
    state.view = 'main';
    render();
  }
});
screen.key(['n'], () => {
  if (inOverlay()) return;
  toggleKind();
});
screen.key(['a'], () => {
  if (inOverlay()) return;
  if (state.view === 'detail') copyAuditHash();
});
screen.key(['g', 'home'], () => {
  if (inOverlay() || state.view !== 'main') return;
  state.suiteIndex = 0;
  render();
});
screen.key(['S-g', 'end'], () => {
  if (inOverlay() || state.view !== 'main') return;
  const s = currentSession();
  state.suiteIndex = s && s.suites ? s.suites.length - 1 : 0;
  render();
});

// ── Boot ─────────────────────────────────────────────────────────────────────
body.focus();
render();

// Self-test affordance: render one frame, then exit. Used to smoke-test the
// blessed layer under a pty without an interactive session.
if (process.env.SENTINEL_DEVLOG_SELFTEST) {
  setTimeout(() => process.exit(0), 600);
}
