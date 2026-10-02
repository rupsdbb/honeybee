'use strict';

// ---------- helpers ----------
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = {
  get(k) { try { return localStorage.getItem('honeybee.' + k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem('honeybee.' + k, v); } catch { /* ignore */ } },
};
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

const ICON = {
  in: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M17 7L7 17M7 9v8h8"/></svg>',
  out: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M7 17L17 7M9 7h8v8"/></svg>',
  self: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M4 12h16M14 6l6 6-6 6"/></svg>',
  copy: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5"/></svg>',
  download: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg>',
  gear: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  ext: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
};

const state = {
  session: null,
  status: null,
  wallets: [],
  detail: null,          // { wallet, snapshot, labels } for the open wallet
  walletId: null,
  tab: 'txs',
  unit: store.get('unit') === 'sat' ? 'sat' : 'btc',
  private: store.get('private') === '1',
  txLimit: 50,
  search: '',
  chainFilter: 'all',
  showUnused: false,
};

// ---------- API ----------
class ApiError extends Error {}

async function api(path, { method = 'GET', body } = {}) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET') {
    opts.headers['x-honeybee'] = '1';
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body ?? {});
  }
  const res = await fetch(path, opts);
  if (res.status === 401 && path !== '/api/login') {
    showLogin();
    throw new ApiError('Session expired');
  }
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;
  if (!res.ok) throw new ApiError(data?.error || `${res.status} ${res.statusText}`);
  return data;
}

// ---------- formatting ----------
function fmtAmount(sats, { sign = false } = {}) {
  if (sats == null) return '–';
  const neg = sats < 0;
  const abs = Math.abs(sats);
  const prefix = neg ? '−' : sign && sats > 0 ? '+' : '';
  if (state.unit === 'sat') return `${prefix}${abs.toLocaleString()} sats`;
  const whole = Math.floor(abs / 1e8).toLocaleString();
  const frac = String(abs % 1e8).padStart(8, '0');
  return `${prefix}${whole}.${frac} BTC`;
}
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const fmtDate = (ts) => (ts ? dateFmt.format(new Date(ts * 1000)) : '');
const shortMid = (s, n = 8) => (s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);
const confsOf = (height) => (height > 0 && state.status?.tip ? state.status.tip.height - height + 1 : 0);
const chainName = (c) => ({ receive: 'Receive', change: 'Change', imported: 'Imported' }[c] || c);

function statusChip(height) {
  if (height <= 0) return '<span class="chip warn">Pending</span>';
  const c = confsOf(height);
  if (c > 0 && c < 6) return `<span class="chip accent">${c} conf</span>`;
  return `<span class="muted small" title="Block ${height.toLocaleString()}">${c > 0 ? c.toLocaleString() + ' conf' : 'Confirmed'}</span>`;
}

function explorer(kind, id) {
  const base = state.status?.explorer_url;
  return base ? `${base}/${kind}/${encodeURIComponent(id)}` : null;
}

function copyBtn(value, title = 'Copy') {
  return `<button class="copy" data-copy="${esc(value)}" title="${esc(title)}" aria-label="${esc(title)}">${ICON.copy}</button>`;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 1800);
}

// ---------- login ----------
function showLogin() {
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-password').value = '';
  $('#login-password').focus();
  events?.close();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  const btn = $('button[type=submit]', e.target);
  btn.disabled = true;
  try {
    await api('/api/login', { method: 'POST', body: { password: $('#login-password').value } });
    $('#login').hidden = true;
    await start();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
});

$('#logout-btn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  showLogin();
});

// ---------- top bar ----------
function renderConn() {
  const s = state.status;
  const el = $('#conn');
  if (!s) { el.innerHTML = ''; return; }
  const ok = s.connected && !s.error;
  const net = s.network === 'bitcoin' ? '' : `<span class="chip warn">${esc(s.network)}</span>`;
  const blake = s.tip?.blake2b ? '<span class="chip accent" title="The chain tip uses the 164-byte BLAKE2b (Bitcoin Knots v2) block header">BLAKE2b</span>' : '';
  const text = ok
    ? `<span class="txt">Block ${s.tip ? s.tip.height.toLocaleString() : '…'}</span><span class="txt txt-long">· ${esc(s.server_version || '')}</span>`
    : `<span class="txt">${esc(s.error || 'Connecting…')}</span>`;
  el.innerHTML = `<span class="dot ${ok ? 'ok' : 'bad'}"></span>${text}${blake}${net}`;
  el.title = `${s.endpoint}${s.server_version ? ' — ' + s.server_version : ''}${s.error ? '\n' + s.error : ''}`;
  $('#version').textContent = `Honeybee ${s.version}`;
  $('#logout-btn').hidden = !s.auth_required;
}

function renderUnit() {
  $$('.seg-btn').forEach((b) => b.classList.toggle('active', b.dataset.unit === state.unit));
  document.body.classList.toggle('private', state.private);
  $('#privacy-btn').classList.toggle('on', state.private);
}

$$('.seg-btn').forEach((b) => b.addEventListener('click', () => {
  state.unit = b.dataset.unit;
  store.set('unit', state.unit);
  renderUnit();
  renderSidebar();
  renderWallet();
}));

$('#privacy-btn').addEventListener('click', () => {
  state.private = !state.private;
  store.set('private', state.private ? '1' : '0');
  renderUnit();
});

$('#menu-btn').addEventListener('click', () => $('#app').classList.toggle('menu-open'));
$('#scrim').addEventListener('click', () => $('#app').classList.remove('menu-open'));

// ---------- sidebar ----------
function renderSidebar() {
  const list = $('#wallet-list');
  list.innerHTML = state.wallets.map((w) => {
    const badge = w.error
      ? '<span class="chip warn" title="' + esc(w.error) + '">!</span>'
      : w.syncing ? '<span class="spinner" title="Syncing"></span>' : '';
    return `<a href="#/w/${esc(w.id)}" class="wallet-item ${w.id === state.walletId ? 'active' : ''}">
      <span class="name">${esc(w.name)}</span>${badge}
      <span class="bal amount">${w.balance ? fmtAmount(w.balance.total) : 'Scanning…'}</span>
    </a>`;
  }).join('');
  const total = state.wallets.reduce((sum, w) => sum + (w.balance?.total || 0), 0);
  $('#portfolio-total').textContent = state.wallets.length ? fmtAmount(total) : '–';
}

$('#add-wallet-btn').addEventListener('click', openAddWallet);

// ---------- routing ----------
function route() {
  const m = location.hash.match(/^#\/w\/([0-9a-f]+)(?:\/(txs|addresses|coins))?/);
  $('#app').classList.remove('menu-open');
  if (m) {
    const changed = state.walletId !== m[1];
    state.walletId = m[1];
    if (m[2]) state.tab = m[2];
    if (changed) {
      state.detail = null;
      state.txLimit = 50;
      state.search = '';
      buildWalletView();
      loadDetail();
    } else {
      buildWalletView();
    }
  } else if (state.wallets.length) {
    location.replace(`#/w/${state.wallets[0].id}`);
    return;
  } else {
    state.walletId = null;
    renderWelcome();
  }
  renderSidebar();
}
window.addEventListener('hashchange', route);

function renderWelcome() {
  $('#main').innerHTML = `<div class="main-inner"><div class="card welcome">
    <img src="/favicon.svg" alt="">
    <h1>Watch your bitcoin, privately</h1>
    <p>Add an xpub/ypub/zpub, an output descriptor, or a list of addresses. Honeybee only asks your own Electrum server,
    and it can never spend: no private keys, no signing, no broadcasting.</p>
    <button class="btn primary" id="welcome-add">Add your first wallet</button>
  </div></div>`;
  $('#welcome-add').addEventListener('click', openAddWallet);
}

// ---------- wallet view ----------
function buildWalletView() {
  const main = $('#main');
  if (main.dataset.wallet !== state.walletId) {
    main.dataset.wallet = state.walletId;
    main.innerHTML = `<div class="main-inner">
      <section id="w-head" class="card card-pad"></section>
      <div id="w-notice"></div>
      <section id="w-receive"></section>
      <section class="card">
        <div id="w-tabs" class="tabs" role="tablist"></div>
        <div id="w-toolbar"></div>
        <div id="w-table"></div>
      </section>
    </div>`;
    main.scrollTop = 0;
  }
  renderToolbar();
  renderWallet();
}

function renderWallet() {
  if (!state.walletId || !$('#w-head')) return;
  const summary = state.wallets.find((w) => w.id === state.walletId);
  if (!summary) {
    $('#w-head').innerHTML = '<div class="empty">Wallet not found.</div>';
    return;
  }
  const snap = state.detail?.wallet.id === state.walletId ? state.detail.snapshot : null;
  const bal = summary.balance;
  const kind = summary.kind === 'addresses' ? `${summary.address_count} address${summary.address_count === 1 ? '' : 'es'}` : 'HD wallet';
  const sync = summary.syncing ? '<span class="chip"><span class="spinner"></span> Syncing</span>' : '';
  $('#w-head').innerHTML = `<div class="wallet-head">
    <div>
      <div class="wallet-title"><h1>${esc(summary.name)}</h1><span class="chip">${esc(kind)}</span>${sync}</div>
      <div class="balance-big amount">${bal ? fmtAmount(bal.total) : '<span class="muted">Scanning…</span>'}</div>
      ${bal ? `<div class="balance-sub">
        <span>Confirmed <b class="amount">${fmtAmount(bal.confirmed)}</b></span>
        ${bal.unconfirmed ? `<span>Pending <b class="amount ${bal.unconfirmed > 0 ? 'pos' : 'neg'}">${fmtAmount(bal.unconfirmed, { sign: true })}</b></span>` : ''}
        <span>${summary.tx_count.toLocaleString()} transaction${summary.tx_count === 1 ? '' : 's'}</span>
      </div>` : ''}
    </div>
    <div class="wallet-actions">
      <button class="btn small" data-action="rescan" title="Forget cached history and scan again">${ICON.refresh} Rescan</button>
      <a class="btn small" href="/api/wallets/${esc(summary.id)}/export.csv" download title="Download transaction history as CSV">${ICON.download} CSV</a>
      <button class="btn small" data-action="settings">${ICON.gear} Settings</button>
    </div>
  </div>`;

  $('#w-notice').innerHTML = summary.error
    ? `<div class="notice">⚠ ${esc(summary.error)}</div>`
    : '';

  renderReceive(snap);
  renderTabs(snap);
  renderTable(snap);
}

function renderReceive(snap) {
  const el = $('#w-receive');
  const next = snap?.next_receive;
  if (!next) { el.innerHTML = ''; el.className = ''; return; }
  if (el.dataset.addr === next.address) return;
  el.dataset.addr = next.address;
  el.className = 'card card-pad';
  const a = next.address;
  const highlighted = a.length > 16
    ? `<b>${esc(a.slice(0, 6))}</b>${esc(a.slice(6, -6))}<b>${esc(a.slice(-6))}</b>`
    : esc(a);
  // Uppercase bech32 makes for a smaller QR code (alphanumeric mode).
  const isBech32 = /^(bc|tb|bcrt)1/i.test(a);
  const uri = isBech32 ? `BITCOIN:${a.toUpperCase()}` : `bitcoin:${a}`;
  el.innerHTML = `<div class="receive">
    <div>
      <div class="muted small">Next unused receive address · index ${next.index}</div>
      <div class="addr">${highlighted}</div>
      <div class="row-inline">
        <button class="btn small" data-copy="${esc(a)}">${ICON.copy} Copy address</button>
        ${explorer('address', a) ? `<a class="btn small" href="${esc(explorer('address', a))}" target="_blank" rel="noopener noreferrer">${ICON.ext} Explorer</a>` : ''}
      </div>
    </div>
    <div class="qr"><img src="/api/qr?data=${encodeURIComponent(uri)}" alt="QR code for ${esc(a)}"></div>
  </div>`;
}

function renderTabs(snap) {
  const counts = {
    txs: snap?.txs.length,
    addresses: snap?.addresses.filter((a) => a.tx_count > 0).length,
    coins: snap?.utxos.length,
  };
  const tabs = [['txs', 'Transactions'], ['addresses', 'Addresses'], ['coins', 'Coins']];
  $('#w-tabs').innerHTML = tabs.map(([id, name]) =>
    `<button class="tab ${state.tab === id ? 'active' : ''}" role="tab" data-tab="${id}">${name}${counts[id] != null ? `<span class="count">${counts[id].toLocaleString()}</span>` : ''}</button>`,
  ).join('');
}

function renderToolbar() {
  const el = $('#w-toolbar');
  if (!el) return;
  if (el.dataset.tab === state.tab) return;
  el.dataset.tab = state.tab;
  const search = `<input type="search" id="search" placeholder="${state.tab === 'txs' ? 'Search txid or label' : 'Search address or txid'}" value="${esc(state.search)}">`;
  if (state.tab === 'addresses') {
    el.innerHTML = `<div class="toolbar">${search}
      <select id="chain-filter" aria-label="Chain">
        <option value="all">All chains</option><option value="receive">Receive</option>
        <option value="change">Change</option><option value="imported">Imported</option>
      </select>
      <label><input type="checkbox" id="show-unused" ${state.showUnused ? 'checked' : ''}> Show unused</label>
    </div>`;
    $('#chain-filter').value = state.chainFilter;
  } else {
    el.innerHTML = `<div class="toolbar">${search}</div>`;
  }
}

function renderTable(snap) {
  const el = $('#w-table');
  if (!el) return;
  if (!snap) {
    el.innerHTML = '<div class="empty"><span class="spinner"></span> Scanning addresses…</div>';
    return;
  }
  if (state.tab === 'txs') el.innerHTML = txTable(snap);
  else if (state.tab === 'addresses') el.innerHTML = addressTable(snap);
  else el.innerHTML = coinTable(snap);
}

function txTable(snap) {
  const labels = state.detail.labels || {};
  const q = state.search.trim().toLowerCase();
  const rows = snap.txs.filter((t) => !q || t.txid.includes(q) || (labels[t.txid] || '').toLowerCase().includes(q));
  if (!rows.length) return `<div class="empty">${snap.txs.length ? 'No matching transactions.' : 'No transactions yet.'}</div>`;
  const shown = rows.slice(0, state.txLimit);
  return `<div class="table-wrap"><table>
    <thead><tr><th>Date</th><th class="hide-mobile">Label / transaction</th><th class="num">Amount</th><th class="num hide-mobile">Balance</th><th class="num">Status</th></tr></thead>
    <tbody>${shown.map((t) => {
      const dir = t.net > 0 ? 'in' : t.net < 0 ? 'out' : 'self';
      const label = labels[t.txid];
      return `<tr class="clickable" data-tx="${esc(t.txid)}">
        <td><span class="tx-dir ${dir}">${ICON[dir]}</span>${t.time ? esc(fmtDate(t.time)) : '<span class="muted">Unconfirmed</span>'}
          <span class="mobile-sub">${esc(label || shortMid(t.txid, 6))}</span></td>
        <td class="label-cell hide-mobile">${label ? esc(label) : `<span class="mono muted">${esc(shortMid(t.txid, 10))}</span>`}</td>
        <td class="num amount ${t.net > 0 ? 'pos' : t.net < 0 ? 'neg' : ''}">${fmtAmount(t.net, { sign: true })}</td>
        <td class="num amount muted hide-mobile">${fmtAmount(t.balance_after)}</td>
        <td class="num">${statusChip(t.height)}</td>
      </tr>`;
    }).join('')}</tbody></table></div>
    ${rows.length > shown.length ? `<div class="more"><button class="btn small" data-action="more">Show more (${(rows.length - shown.length).toLocaleString()} left)</button></div>` : ''}`;
}

function addressTable(snap) {
  const q = state.search.trim().toLowerCase();
  const rows = snap.addresses.filter((a) =>
    (state.showUnused || a.tx_count > 0)
    && (state.chainFilter === 'all' || a.chain === state.chainFilter)
    && (!q || a.address.toLowerCase().includes(q)));
  if (!rows.length) return `<div class="empty">${state.showUnused ? 'No matching addresses.' : 'No used addresses yet. Tick “Show unused” to see the scanned ones.'}</div>`;
  return `<div class="table-wrap"><table>
    <thead><tr><th>Path</th><th>Address</th><th class="num">Txs</th><th class="num hide-mobile">Received</th><th class="num">Balance</th></tr></thead>
    <tbody>${rows.map((a) => `<tr>
      <td class="muted">${chainName(a.chain)} #${a.index}</td>
      <td><span class="mono">${esc(a.address)}</span> ${copyBtn(a.address, 'Copy address')}
        ${explorer('address', a.address) ? `<a class="copy" href="${esc(explorer('address', a.address))}" target="_blank" rel="noopener noreferrer" title="Open in explorer">${ICON.ext}</a>` : ''}</td>
      <td class="num">${a.tx_count || '<span class="muted">0</span>'}</td>
      <td class="num amount muted hide-mobile">${fmtAmount(a.received)}</td>
      <td class="num amount">${a.balance ? fmtAmount(a.balance) : '<span class="muted">–</span>'}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function coinTable(snap) {
  const q = state.search.trim().toLowerCase();
  const rows = snap.utxos.filter((u) => !q || u.address.toLowerCase().includes(q) || u.txid.includes(q));
  if (!rows.length) return `<div class="empty">${snap.utxos.length ? 'No matching coins.' : 'No unspent coins.'}</div>`;
  const total = rows.reduce((s, u) => s + u.value, 0);
  return `<div class="table-wrap"><table>
    <thead><tr><th>Outpoint</th><th>Address</th><th class="num">Amount</th><th class="num">Status</th></tr></thead>
    <tbody>${rows.map((u) => `<tr class="clickable" data-tx="${esc(u.txid)}">
      <td class="mono">${esc(shortMid(u.txid, 8))}:${u.vout}</td>
      <td><span class="mono">${esc(shortMid(u.address, 10))}</span> <span class="muted small">${chainName(u.chain)} #${u.index}</span></td>
      <td class="num amount">${fmtAmount(u.value)}</td>
      <td class="num">${statusChip(u.height)}</td>
    </tr>`).join('')}</tbody>
    <tfoot><tr><td colspan="2" class="muted">${rows.length.toLocaleString()} coin${rows.length === 1 ? '' : 's'}</td><td class="num amount"><b>${fmtAmount(total)}</b></td><td></td></tr></tfoot>
    </table></div>`;
}

// Delegated events for the wallet view.
$('#main').addEventListener('click', (e) => {
  const tab = e.target.closest('[data-tab]');
  if (tab) {
    state.tab = tab.dataset.tab;
    state.search = '';
    history.replaceState(null, '', `#/w/${state.walletId}/${state.tab}`);
    buildWalletView();
    return;
  }
  const action = e.target.closest('[data-action]')?.dataset.action;
  if (action === 'more') { state.txLimit += 100; renderWallet(); return; }
  if (action === 'rescan') { rescan(); return; }
  if (action === 'settings') { openSettings(); return; }
  if (e.target.closest('[data-copy], a')) return;
  const tx = e.target.closest('[data-tx]');
  if (tx) openTx(tx.dataset.tx);
});

$('#main').addEventListener('input', (e) => {
  if (e.target.id === 'search') {
    state.search = e.target.value;
    state.txLimit = 50;
    renderTable(state.detail?.snapshot);
  }
});

$('#main').addEventListener('change', (e) => {
  if (e.target.id === 'chain-filter') state.chainFilter = e.target.value;
  else if (e.target.id === 'show-unused') state.showUnused = e.target.checked;
  else return;
  renderTable(state.detail?.snapshot);
});

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  e.stopPropagation();
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    toast('Copied');
  } catch {
    toast('Copy failed (clipboard needs HTTPS or localhost)');
  }
});

async function rescan() {
  try {
    await api(`/api/wallets/${state.walletId}/rescan`, { method: 'POST' });
    toast('Rescanning…');
  } catch (ex) { toast(ex.message); }
}

// ---------- modal ----------
const modal = $('#modal');
function openModal(title, html) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = html;
  if (!modal.open) modal.showModal();
}
function closeModal() { if (modal.open) modal.close(); }
modal.addEventListener('click', (e) => {
  if (e.target === modal || e.target.closest('[data-close]')) closeModal();
});

// ---------- transaction details ----------
async function openTx(txid) {
  openModal('Transaction', '<div class="empty"><span class="spinner"></span></div>');
  let data;
  try {
    data = await api(`/api/wallets/${state.walletId}/tx/${txid}`);
  } catch (ex) {
    $('#modal-body').innerHTML = `<p class="form-error">${esc(ex.message)}</p>`;
    return;
  }
  const t = data.tx;
  const mineChip = (m) => (m ? `<span class="chip accent">${chainName(m.chain)} #${m.index}</span>` : '');
  const feeRate = t.fee != null && t.vsize ? (t.fee / t.vsize).toFixed(t.fee / t.vsize < 10 ? 2 : 1) : null;
  const link = explorer('tx', t.txid);
  $('#modal-body').innerHTML = `
    <dl class="kv">
      <dt>Amount</dt><dd class="amount ${t.net > 0 ? 'pos' : t.net < 0 ? 'neg' : ''}"><b>${fmtAmount(t.net, { sign: true })}</b></dd>
      <dt>Status</dt><dd>${statusChip(t.height)} ${t.height > 0 ? `<span class="muted small">in block ${t.height.toLocaleString()}</span>` : ''}</dd>
      <dt>${t.height > 0 ? 'Date' : 'First seen'}</dt><dd>${esc(fmtDate(t.time)) || '–'}</dd>
      <dt>Fee</dt><dd>${t.fee != null ? `<span class="amount">${fmtAmount(t.fee)}</span> <span class="muted">· ${feeRate} sat/vB</span>` : '<span class="muted">unknown</span>'}</dd>
      <dt>Size</dt><dd>${t.vsize.toLocaleString()} vB <span class="muted">· ${t.weight.toLocaleString()} WU · ${t.size.toLocaleString()} bytes${t.rbf ? ' · RBF' : ''}</span></dd>
      <dt>Transaction ID</dt><dd><span class="mono">${esc(t.txid)}</span> ${copyBtn(t.txid, 'Copy txid')}
        ${link ? `<a class="copy" href="${esc(link)}" target="_blank" rel="noopener noreferrer" title="Open in explorer">${ICON.ext}</a>` : ''}</dd>
    </dl>
    <form id="label-form" class="field">
      <span>Label</span>
      <div class="row"><input id="label-input" maxlength="200" placeholder="e.g. Salary, Coffee with Satoshi" value="${esc(data.label || '')}">
      <button class="btn" type="submit">Save</button></div>
    </form>
    <div class="io">
      <div><h4>Inputs (${t.inputs.length})</h4>${t.inputs.map((i) => `<div class="io-item ${i.mine ? 'mine' : ''}">
        <span class="mono">${i.coinbase ? 'Coinbase (newly minted)' : esc(i.address || `${shortMid(i.prev_txid, 8)}:${i.vout}`)}</span>
        <span class="meta"><span>${mineChip(i.mine)}</span><span class="amount">${i.value != null ? fmtAmount(i.value) : ''}</span></span>
      </div>`).join('')}</div>
      <div><h4>Outputs (${t.outputs.length})</h4>${t.outputs.map((o) => `<div class="io-item ${o.mine ? 'mine' : ''}">
        <span class="mono">${esc(o.address)}</span>
        <span class="meta"><span>${mineChip(o.mine)}${o.spent_by_wallet ? ' <span class="chip">spent</span>' : ''}</span><span class="amount">${fmtAmount(o.value)}</span></span>
      </div>`).join('')}</div>
    </div>`;
  $('#label-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const label = $('#label-input').value;
    try {
      await api(`/api/wallets/${state.walletId}/labels/${t.txid}`, { method: 'PUT', body: { label } });
      if (state.detail) state.detail.labels[t.txid] = label.trim() || undefined;
      renderTable(state.detail?.snapshot);
      toast('Label saved');
    } catch (ex) { toast(ex.message); }
  });
}

// ---------- add wallet ----------
function openAddWallet() {
  const gap = 20;
  openModal('Add a watch-only wallet', `
    <form id="add-form">
      <label class="field"><span>Name</span><input id="add-name" maxlength="60" placeholder="Cold storage" required></label>
      <label class="field"><span>Public key, descriptor or addresses</span>
        <textarea id="add-input" spellcheck="false" autocomplete="off" placeholder="zpub6r…  or  wpkh([fingerprint/84h/0h/0h]xpub…/<0;1>/*)  or  bc1q… bc1q…" required></textarea>
        <span class="hint">Accepted: xpub/ypub/zpub (and testnet tpub/upub/vpub), output descriptors (single-sig, multisig, taproot; one multipath or a receive + change pair), or addresses separated by spaces, commas or new lines. Never paste a seed phrase or private key.</span>
      </label>
      <div class="row">
        <label class="field"><span>Script type</span>
          <select id="add-type">
            <option value="auto">Auto (from key prefix)</option>
            <option value="wpkh">Native SegWit (bc1q…, BIP84)</option>
            <option value="tr">Taproot (bc1p…, BIP86)</option>
            <option value="sh_wpkh">Nested SegWit (3…, BIP49)</option>
            <option value="pkh">Legacy (1…, BIP44)</option>
          </select>
          <span class="hint">Only needed for a plain xpub/tpub.</span>
        </label>
        <label class="field"><span>Gap limit</span><input id="add-gap" type="number" min="1" max="1000" value="${gap}">
          <span class="hint">Unused addresses to scan past the last used one.</span></label>
      </div>
      <div id="add-preview"></div>
      <p id="add-error" class="form-error" hidden></p>
      <div class="modal-actions">
        <button type="button" class="btn" data-close>Cancel</button>
        <button type="submit" class="btn primary" id="add-submit">Watch wallet</button>
      </div>
    </form>`);
  $('#add-name').focus();
  const preview = debounce(previewWallet, 350);
  $('#add-input').addEventListener('input', preview);
  $('#add-type').addEventListener('change', previewWallet);
  $('#add-form').addEventListener('submit', submitWallet);
}

// Catch secrets in the browser so they are never even sent to the server.
function secretWarning(input) {
  if (/\b[xyzYZtuvUV]prv[1-9A-HJ-NP-Za-km-z]{20,}/.test(input)) {
    return 'That is a PRIVATE key. Honeybee is watch-only: use the matching xpub/zpub instead.';
  }
  const words = input.trim().split(/\s+/);
  if ([12, 15, 18, 21, 24].includes(words.length) && words.every((w) => /^[a-z]+$/.test(w))) {
    return 'That looks like a seed phrase. Never enter it here: Honeybee only needs an xpub, descriptor or addresses.';
  }
  if (/\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b/.test(input) && !/[xyzYZtuvUV]pub/.test(input)) {
    return 'That looks like a private key (WIF). Honeybee is watch-only: enter addresses or an xpub instead.';
  }
  return null;
}

async function previewWallet() {
  const input = $('#add-input')?.value.trim();
  const box = $('#add-preview');
  const err = $('#add-error');
  if (!box) return;
  err.hidden = true;
  if (!input) { box.innerHTML = ''; return; }
  const secret = secretWarning(input);
  if (secret) {
    box.innerHTML = '';
    err.textContent = secret;
    err.hidden = false;
    return;
  }
  try {
    const p = await api('/api/wallets/preview', { method: 'POST', body: { input, script_type: $('#add-type').value } });
    const section = (title, list) => (list?.length
      ? `<h4>${title}</h4><ol start="0">${list.map((a) => `<li>${esc(a)}</li>`).join('')}</ol>` : '');
    box.innerHTML = `<div class="preview">
      ${section('First receive addresses', p.addresses.receive)}
      ${section('First change addresses', p.addresses.change?.slice(0, 2))}
      ${section('Addresses', p.addresses.imported)}
      <p class="muted small">Check that these match your wallet before continuing.</p>
    </div>`;
  } catch (ex) {
    box.innerHTML = '';
    err.textContent = ex.message;
    err.hidden = false;
  }
}

async function submitWallet(e) {
  e.preventDefault();
  const err = $('#add-error');
  const btn = $('#add-submit');
  const secret = secretWarning($('#add-input').value);
  if (secret) {
    err.textContent = secret;
    err.hidden = false;
    return;
  }
  err.hidden = true;
  btn.disabled = true;
  try {
    const w = await api('/api/wallets', {
      method: 'POST',
      body: {
        name: $('#add-name').value,
        input: $('#add-input').value,
        script_type: $('#add-type').value,
        gap_limit: Number($('#add-gap').value) || undefined,
      },
    });
    closeModal();
    await loadWallets();
    location.hash = `#/w/${w.id}`;
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

// ---------- wallet settings ----------
function openSettings() {
  const w = state.wallets.find((x) => x.id === state.walletId);
  if (!w) return;
  const descs = w.descriptors.map((d, i) => `<div class="field"><span>${w.descriptors.length > 1 ? (i === 0 ? 'Receive descriptor' : 'Change descriptor') : 'Descriptor'}
    ${copyBtn(d, 'Copy descriptor')}</span><div class="desc-box">${esc(d)}</div></div>`).join('');
  openModal('Wallet settings', `
    <form id="settings-form">
      <label class="field"><span>Name</span><input id="set-name" maxlength="60" value="${esc(w.name)}" required></label>
      ${w.kind === 'descriptor' ? `<label class="field"><span>Gap limit</span><input id="set-gap" type="number" min="1" max="1000" value="${w.gap_limit}">
        <span class="hint">Raising it scans further; to scan less, lower it and then use Rescan.</span></label>` : ''}
      ${descs}
      <p id="set-error" class="form-error" hidden></p>
      <div class="modal-actions">
        <button type="button" class="btn danger" id="delete-wallet">Remove wallet</button>
        <span class="spacer"></span>
        <button type="button" class="btn" data-close>Cancel</button>
        <button type="submit" class="btn primary">Save</button>
      </div>
    </form>`);
  $('#settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api(`/api/wallets/${w.id}`, {
        method: 'PATCH',
        body: { name: $('#set-name').value, gap_limit: $('#set-gap') ? Number($('#set-gap').value) : undefined },
      });
      closeModal();
      await loadWallets();
      renderWallet();
    } catch (ex) {
      $('#set-error').textContent = ex.message;
      $('#set-error').hidden = false;
    }
  });
  $('#delete-wallet').addEventListener('click', async () => {
    if (!confirm(`Stop watching “${w.name}”? Its labels are deleted too. (No funds are affected.)`)) return;
    try {
      await api(`/api/wallets/${w.id}`, { method: 'DELETE' });
      closeModal();
      state.walletId = null;
      $('#main').dataset.wallet = '';
      await loadWallets();
      location.hash = '#/';
      route();
    } catch (ex) { toast(ex.message); }
  });
}

// ---------- data loading ----------
async function loadStatus() {
  try {
    state.status = await api('/api/status');
    renderConn();
    if (state.detail) renderWallet();
  } catch { /* shown via login or retried on next event */ }
}

async function loadWallets() {
  state.wallets = await api('/api/wallets');
  renderSidebar();
}

async function loadDetail() {
  const id = state.walletId;
  if (!id) return;
  try {
    const d = await api(`/api/wallets/${id}`);
    if (state.walletId !== id) return;
    state.detail = d;
    const i = state.wallets.findIndex((w) => w.id === id);
    if (i >= 0) state.wallets[i] = d.wallet;
    renderSidebar();
    renderWallet();
  } catch (ex) {
    if (ex instanceof ApiError && /not found/i.test(ex.message)) {
      location.hash = '#/';
    }
  }
}

const refreshDetail = debounce(loadDetail, 300);
const refreshWallets = debounce(() => loadWallets().then(renderWallet).catch(() => {}), 300);
const refreshStatus = debounce(loadStatus, 200);

let events = null;
function connectEvents() {
  events?.close();
  events = new EventSource('/api/events');
  events.onmessage = (msg) => {
    let ev;
    try { ev = JSON.parse(msg.data); } catch { return; }
    if (ev.type === 'status') refreshStatus();
    else if (ev.type === 'wallet') {
      refreshWallets();
      if (ev.id === state.walletId) refreshDetail();
    } else if (ev.type === 'wallet_removed') {
      refreshWallets();
      if (ev.id === state.walletId) location.hash = '#/';
    } else if (ev.type === 'resync') {
      refreshStatus(); refreshWallets(); refreshDetail();
    }
  };
  events.onerror = debounce(async () => {
    // EventSource retries by itself; check whether the session expired.
    const s = await fetch('/api/session').then((r) => r.json()).catch(() => null);
    if (s && s.auth_required && !s.authenticated) showLogin();
  }, 2000);
}

async function start() {
  $('#app').hidden = false;
  renderUnit();
  await Promise.all([loadStatus(), loadWallets()]);
  route();
  connectEvents();
}

(async function init() {
  try {
    state.session = await fetch('/api/session').then((r) => r.json());
  } catch {
    document.body.textContent = 'Cannot reach the Honeybee server.';
    return;
  }
  if (state.session.auth_required && !state.session.authenticated) showLogin();
  else start();
})();
