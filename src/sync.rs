//! Keeps every wallet in sync with the Electrum server.
//!
//! For each wallet: derive addresses until `gap_limit` unused ones follow the
//! last used one, subscribe to their script hashes, fetch the history of any
//! script hash whose status changed, fetch the transactions (and their parents,
//! for fees), then compute a [`Snapshot`] that the web UI reads.
//! Server notifications trigger re-syncs.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use futures::stream::{self, StreamExt, TryStreamExt};
use miniscript::bitcoin::hashes::{Hash, sha256};
use miniscript::bitcoin::{Network, OutPoint, Script, ScriptBuf, Transaction, Txid, consensus};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::expected_genesis;
use crate::electrum::{ElectrumClient, ElectrumError};
use crate::header;
use crate::store::{Store, WalletRecord};
use crate::wallet::{Chain, ChainKind, address_of, script_at};

const PARALLEL_REQUESTS: usize = 24;
/// Block times this close to the tip may change in a reorg, so are refetched.
const REORG_SAFETY: i64 = 6;

/// Electrum script hash: reversed SHA256 of the output script, hex encoded.
pub fn script_hash(script: &Script) -> String {
    let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Status,
    Wallet { id: String },
    WalletRemoved { id: String },
}

#[derive(Debug, Clone)]
pub struct AddrEntry {
    pub script_hash: String,
    pub script: ScriptBuf,
    pub address: String,
    pub chain: ChainKind,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistItem {
    pub txid: Txid,
    /// > 0: confirmed at this height. 0 or -1: in the mempool.
    pub height: i64,
}

/// History of a script hash, tagged with the subscription status it was fetched for.
type History = (Option<String>, Vec<HistItem>);

#[derive(Default)]
struct WalletState {
    entries: Vec<AddrEntry>,
    /// Indexes into `entries`, one list per chain (parallel to `WalletRt::chains`).
    by_chain: Vec<Vec<usize>>,
    histories: HashMap<String, History>,
}

#[derive(Default)]
struct SyncCtl {
    running: bool,
    again: bool,
    error: Option<String>,
    last_sync: Option<u64>,
}

pub struct WalletRt {
    pub id: String,
    record: Mutex<WalletRecord>,
    chains: Vec<Chain>,
    state: tokio::sync::Mutex<WalletState>,
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    ctl: Mutex<SyncCtl>,
    deleted: AtomicBool,
}

impl WalletRt {
    pub fn record(&self) -> WalletRecord {
        self.record.lock().unwrap().clone()
    }

    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.snapshot.read().unwrap().clone()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Balance {
    pub confirmed: i64,
    pub unconfirmed: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxRow {
    pub txid: String,
    pub height: i64,
    pub time: Option<u64>,
    /// Net effect on the wallet, in sats.
    pub net: i64,
    pub fee: Option<u64>,
    pub vsize: u64,
    pub balance_after: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UtxoRow {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub address: String,
    pub chain: ChainKind,
    pub index: u32,
    pub height: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddrRow {
    pub address: String,
    pub chain: ChainKind,
    pub index: u32,
    pub tx_count: usize,
    pub received: u64,
    pub balance: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddrRef {
    pub address: String,
    pub index: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub balance: Balance,
    /// Newest first.
    pub txs: Vec<TxRow>,
    pub utxos: Vec<UtxoRow>,
    pub addresses: Vec<AddrRow>,
    pub next_receive: Option<AddrRef>,
    #[serde(skip)]
    pub mine: HashMap<ScriptBuf, (ChainKind, u32, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletSummary {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub gap_limit: u32,
    pub descriptors: Vec<String>,
    pub address_count: usize,
    pub balance: Option<Balance>,
    pub tx_count: usize,
    pub syncing: bool,
    pub error: Option<String>,
    pub last_sync: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Tip {
    pub height: i64,
    /// The tip header is a 164-byte BLAKE2b (Bitcoin Knots v2) header.
    pub blake2b: bool,
}

#[derive(Default)]
struct Subscriptions {
    epoch: u64,
    status: HashMap<String, Option<String>>,
}

pub struct Manager {
    client: ElectrumClient,
    store: Arc<Store>,
    pub network: Network,
    wallets: RwLock<Vec<Arc<WalletRt>>>,
    /// script hash -> ids of wallets watching it
    watchers: Mutex<HashMap<String, HashSet<String>>>,
    subs: Mutex<Subscriptions>,
    txs: Mutex<HashMap<Txid, Arc<Transaction>>>,
    times: Mutex<HashMap<i64, u32>>,
    first_seen: Mutex<HashMap<Txid, u64>>,
    tip: Mutex<Option<Tip>>,
    chain_error: Mutex<Option<String>>,
    events: broadcast::Sender<Event>,
}

impl Manager {
    pub fn new(client: ElectrumClient, store: Arc<Store>, network: Network) -> anyhow::Result<Arc<Manager>> {
        let (events, _) = broadcast::channel(256);
        let mgr = Arc::new(Manager {
            client,
            store,
            network,
            wallets: RwLock::new(Vec::new()),
            watchers: Mutex::new(HashMap::new()),
            subs: Mutex::new(Subscriptions::default()),
            txs: Mutex::new(HashMap::new()),
            times: Mutex::new(HashMap::new()),
            first_seen: Mutex::new(HashMap::new()),
            tip: Mutex::new(None),
            chain_error: Mutex::new(None),
            events,
        });
        for record in mgr.store.wallets()? {
            match mgr.make_runtime(record.clone()) {
                Ok(w) => mgr.wallets.write().unwrap().push(w),
                Err(e) => warn!("skipping wallet {} ({}): {e}", record.id, record.name),
            }
        }
        Ok(mgr)
    }

    fn make_runtime(&self, record: WalletRecord) -> Result<Arc<WalletRt>, String> {
        let chains = record.spec.chains(self.network)?;
        Ok(Arc::new(WalletRt {
            id: record.id.clone(),
            record: Mutex::new(record),
            state: tokio::sync::Mutex::new(WalletState {
                by_chain: vec![Vec::new(); chains.len()],
                ..Default::default()
            }),
            chains,
            snapshot: RwLock::new(None),
            ctl: Mutex::new(SyncCtl::default()),
            deleted: AtomicBool::new(false),
        }))
    }

    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn notify(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub fn client(&self) -> &ElectrumClient {
        &self.client
    }

    pub fn tip(&self) -> Option<Tip> {
        self.tip.lock().unwrap().clone()
    }

    pub fn chain_error(&self) -> Option<String> {
        self.chain_error.lock().unwrap().clone()
    }

    pub fn wallets(&self) -> Vec<Arc<WalletRt>> {
        self.wallets.read().unwrap().clone()
    }

    pub fn wallet(&self, id: &str) -> Option<Arc<WalletRt>> {
        self.wallets.read().unwrap().iter().find(|w| w.id == id).cloned()
    }

    pub fn summary(&self, w: &WalletRt) -> WalletSummary {
        let record = w.record();
        let snapshot = w.snapshot();
        let ctl = w.ctl.lock().unwrap();
        let (descriptors, address_count) = match &record.spec {
            crate::wallet::WalletSpec::Descriptor { receive, change } => {
                (std::iter::once(receive.clone()).chain(change.clone()).collect(), 0)
            }
            crate::wallet::WalletSpec::Addresses { addresses } => (Vec::new(), addresses.len()),
        };
        WalletSummary {
            id: record.id,
            name: record.name,
            kind: record.spec.kind_name(),
            gap_limit: record.gap_limit,
            descriptors,
            address_count,
            balance: snapshot.as_ref().map(|s| s.balance),
            tx_count: snapshot.as_ref().map_or(0, |s| s.txs.len()),
            syncing: ctl.running,
            error: ctl.error.clone(),
            last_sync: ctl.last_sync,
        }
    }

    /// Start background tasks: react to (re)connections and server notifications.
    pub fn start(self: &Arc<Self>) {
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut status = mgr.client.status();
            let mut seen_epoch = 0;
            loop {
                let s = status.borrow_and_update().clone();
                if s.connected && s.epoch != seen_epoch {
                    seen_epoch = s.epoch;
                    mgr.on_connected(s.epoch, s.genesis_hash.as_deref()).await;
                }
                mgr.notify(Event::Status);
                if status.changed().await.is_err() {
                    return;
                }
            }
        });

        let mgr = self.clone();
        tokio::spawn(async move {
            let mut notes = mgr.client.notifications();
            loop {
                match notes.recv().await {
                    Ok(n) => mgr.on_notification(&n.method, &n.params),
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        warn!("missed {missed} server notifications; resyncing everything");
                        mgr.sync_all();
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    async fn on_connected(self: &Arc<Self>, epoch: u64, genesis: Option<&str>) {
        if let (Some(expected), Some(actual)) = (expected_genesis(self.network), genesis)
            && expected != actual
        {
            let msg = format!(
                "The Electrum server is on a different chain (genesis {actual}) than the configured network ({}).",
                self.network
            );
            warn!("{msg}");
            *self.chain_error.lock().unwrap() = Some(msg);
            return;
        }
        *self.chain_error.lock().unwrap() = None;
        {
            let mut subs = self.subs.lock().unwrap();
            subs.epoch = epoch;
            subs.status.clear();
        }
        match self.client.call("blockchain.headers.subscribe", json!([])).await {
            Ok(v) => self.set_tip(&v),
            Err(e) => warn!("headers.subscribe: {e}"),
        }
        self.sync_all();
    }

    fn set_tip(&self, v: &Value) {
        let Some(height) = v.get("height").and_then(Value::as_i64) else { return };
        let blake2b = v.get("hex").and_then(Value::as_str).and_then(header::parse_hex).is_some_and(|h| h.v2);
        let previous = self.tip.lock().unwrap().replace(Tip { height, blake2b });
        if previous.is_some_and(|p| p.height >= height) {
            // Reorg (or a repeat): forget block times that may have changed.
            self.times.lock().unwrap().retain(|h, _| *h < height - REORG_SAFETY);
        }
        debug!("tip {height}");
        self.notify(Event::Status);
    }

    fn on_notification(self: &Arc<Self>, method: &str, params: &Value) {
        match method {
            "blockchain.headers.subscribe" => {
                if let Some(h) = params.get(0) {
                    self.set_tip(h);
                }
            }
            "blockchain.scripthash.subscribe" => {
                let (Some(sh), Some(status)) = (params.get(0).and_then(Value::as_str), params.get(1)) else {
                    return;
                };
                let status = status.as_str().map(str::to_string);
                self.subs.lock().unwrap().status.insert(sh.to_string(), status);
                let ids: Vec<String> =
                    self.watchers.lock().unwrap().get(sh).map(|s| s.iter().cloned().collect()).unwrap_or_default();
                for id in ids {
                    if let Some(w) = self.wallet(&id) {
                        self.request_sync(w);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn sync_all(self: &Arc<Self>) {
        for w in self.wallets() {
            self.request_sync(w);
        }
    }

    /// Schedule a sync. If one is running, another pass follows it.
    pub fn request_sync(self: &Arc<Self>, w: Arc<WalletRt>) {
        {
            let mut ctl = w.ctl.lock().unwrap();
            if ctl.running {
                ctl.again = true;
                return;
            }
            ctl.running = true;
            ctl.again = false;
        }
        self.notify(Event::Wallet { id: w.id.clone() });
        let mgr = self.clone();
        tokio::spawn(async move {
            loop {
                // Coalesce bursts of notifications (e.g. a new block).
                tokio::time::sleep(Duration::from_millis(250)).await;
                w.ctl.lock().unwrap().again = false;
                let started = std::time::Instant::now();
                let result = mgr.sync_wallet(&w).await;
                let again = {
                    let mut ctl = w.ctl.lock().unwrap();
                    match &result {
                        Ok(()) => {
                            ctl.error = None;
                            ctl.last_sync = Some(now_secs());
                        }
                        Err(e) => ctl.error = Some(format!("{e:#}")),
                    }
                    let again = ctl.again && !w.deleted.load(Ordering::Relaxed) && result.is_ok();
                    ctl.running = again;
                    again
                };
                match &result {
                    Ok(()) => debug!("synced wallet {} in {:?}", w.id, started.elapsed()),
                    Err(e) => warn!("syncing wallet {}: {e:#}", w.id),
                }
                mgr.notify(Event::Wallet { id: w.id.clone() });
                if !again {
                    break;
                }
            }
        });
    }

    fn status_of(&self, sh: &str) -> Option<String> {
        self.subs.lock().unwrap().status.get(sh).cloned().flatten()
    }

    async fn subscribe_all(&self, wallet_id: &str, hashes: Vec<String>) -> anyhow::Result<()> {
        {
            let mut watchers = self.watchers.lock().unwrap();
            for sh in &hashes {
                watchers.entry(sh.clone()).or_default().insert(wallet_id.to_string());
            }
        }
        let (epoch, todo): (u64, Vec<String>) = {
            let subs = self.subs.lock().unwrap();
            (subs.epoch, hashes.into_iter().filter(|sh| !subs.status.contains_key(sh)).collect())
        };
        let results: Vec<(String, Option<String>)> = stream::iter(todo)
            .map(|sh| async move {
                let v = self.client.call("blockchain.scripthash.subscribe", json!([sh])).await?;
                Ok::<_, ElectrumError>((sh, v.as_str().map(str::to_string)))
            })
            .buffer_unordered(PARALLEL_REQUESTS)
            .try_collect()
            .await?;
        let mut subs = self.subs.lock().unwrap();
        if subs.epoch != epoch {
            bail!("reconnected during sync");
        }
        for (sh, status) in results {
            // A notification may already have delivered a newer status.
            subs.status.entry(sh).or_insert(status);
        }
        Ok(())
    }

    async fn sync_wallet(self: &Arc<Self>, w: &Arc<WalletRt>) -> anyhow::Result<()> {
        if let Some(e) = self.chain_error() {
            bail!(e);
        }
        if w.deleted.load(Ordering::Relaxed) {
            return Ok(());
        }
        let gap = w.record.lock().unwrap().gap_limit.max(1) as usize;
        let mut st = w.state.lock().await;
        let st = &mut *st;

        // 1. Discover addresses and subscribe.
        for (ci, chain) in w.chains.iter().enumerate() {
            match chain {
                Chain::Fixed { kind, scripts } => {
                    if st.by_chain[ci].is_empty() {
                        for (i, script) in scripts.iter().enumerate() {
                            self.add_entry(st, ci, *kind, i as u32, script.clone());
                        }
                    }
                    let hashes = st.by_chain[ci].iter().map(|&e| st.entries[e].script_hash.clone()).collect();
                    self.subscribe_all(&w.id, hashes).await?;
                }
                Chain::Ranged { kind, descriptor } => loop {
                    let hashes = st.by_chain[ci].iter().map(|&e| st.entries[e].script_hash.clone()).collect();
                    self.subscribe_all(&w.id, hashes).await?;
                    let last_used =
                        st.by_chain[ci].iter().rposition(|&e| self.status_of(&st.entries[e].script_hash).is_some());
                    let needed = last_used.map_or(0, |i| i + 1) + gap;
                    let have = st.by_chain[ci].len();
                    if have >= needed {
                        break;
                    }
                    for index in have..needed {
                        let script = script_at(descriptor, index as u32).map_err(|e| anyhow!(e))?;
                        self.add_entry(st, ci, *kind, index as u32, script);
                    }
                },
            }
        }

        // 2. Fetch histories whose status changed.
        let mut to_fetch = Vec::new();
        for e in &st.entries {
            match self.status_of(&e.script_hash) {
                None => {
                    st.histories.insert(e.script_hash.clone(), (None, Vec::new()));
                }
                Some(status) => {
                    if st.histories.get(&e.script_hash).and_then(|h| h.0.as_ref()) != Some(&status) {
                        to_fetch.push((e.script_hash.clone(), status));
                    }
                }
            }
        }
        let fetched: Vec<(String, History)> = stream::iter(to_fetch)
            .map(|(sh, status)| async move {
                let v = self.client.call("blockchain.scripthash.get_history", json!([sh])).await?;
                Ok::<_, anyhow::Error>((sh, (Some(status), parse_history(&v)?)))
            })
            .buffer_unordered(PARALLEL_REQUESTS)
            .try_collect()
            .await?;
        st.histories.extend(fetched);

        // 3. Transactions, then missing parents of the ones that spend wallet
        //    coins, so outgoing fees are known. (Parents of purely incoming
        //    transactions can be many and slow to fetch from electrs, so they
        //    are only fetched when the transaction is opened.)
        let mut heights: HashMap<Txid, i64> = HashMap::new();
        for e in &st.entries {
            for item in st.histories.get(&e.script_hash).map(|h| h.1.as_slice()).unwrap_or_default() {
                heights.insert(item.txid, item.height);
            }
        }
        let wallet_txids: Vec<Txid> = heights.keys().copied().collect();
        self.ensure_txs(&wallet_txids).await?;
        let parents: Vec<Txid> = {
            let txs = self.txs.lock().unwrap();
            let mut set = HashSet::new();
            for txid in &wallet_txids {
                if let Some(tx) = txs.get(txid) {
                    let spends_wallet_coin = tx.input.iter().any(|i| heights.contains_key(&i.previous_output.txid));
                    if !tx.is_coinbase() && spends_wallet_coin {
                        set.extend(tx.input.iter().map(|i| i.previous_output.txid));
                    }
                }
            }
            set.into_iter().filter(|t| !txs.contains_key(t)).collect()
        };
        if let Err(e) = self.ensure_txs(&parents).await {
            warn!("could not fetch some parent transactions (fees will be missing): {e:#}");
        }

        // 4. Block times and first-seen times.
        let missing_heights: Vec<i64> = {
            let times = self.times.lock().unwrap();
            let set: HashSet<i64> = heights.values().copied().filter(|h| *h > 0 && !times.contains_key(h)).collect();
            set.into_iter().collect()
        };
        let fetched_times: Vec<(i64, u32)> = stream::iter(missing_heights)
            .map(|h| async move {
                let v = self.client.call("blockchain.block.header", json!([h])).await?;
                let info = v.as_str().and_then(header::parse_hex).ok_or_else(|| anyhow!("bad header at {h}"))?;
                Ok::<_, anyhow::Error>((h, info.time))
            })
            .buffer_unordered(PARALLEL_REQUESTS)
            .try_collect()
            .await?;
        self.times.lock().unwrap().extend(fetched_times);
        {
            let mut first_seen = self.first_seen.lock().unwrap();
            let now = now_secs();
            for (txid, h) in &heights {
                if *h <= 0 {
                    first_seen.entry(*txid).or_insert(now);
                }
            }
        }

        // 5. Snapshot.
        let snapshot = {
            let txs = self.txs.lock().unwrap();
            let times = self.times.lock().unwrap();
            let first_seen = self.first_seen.lock().unwrap();
            build_snapshot(&st.entries, &st.histories, &txs, &times, &first_seen)
        };
        *w.snapshot.write().unwrap() = Some(Arc::new(snapshot));
        Ok(())
    }

    fn add_entry(&self, st: &mut WalletState, chain_idx: usize, chain: ChainKind, index: u32, script: ScriptBuf) {
        let address = address_of(&script, self.network).unwrap_or_else(|| format!("script:{}", script.to_hex_string()));
        st.by_chain[chain_idx].push(st.entries.len());
        st.entries.push(AddrEntry { script_hash: script_hash(&script), script, address, chain, index });
    }

    async fn ensure_txs(&self, txids: &[Txid]) -> anyhow::Result<()> {
        let missing: Vec<Txid> = {
            let txs = self.txs.lock().unwrap();
            txids.iter().filter(|t| !txs.contains_key(*t)).copied().collect()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let keys: Vec<String> = missing.iter().map(|t| t.to_string()).collect();
        let cached = self.store.raw_txs(&keys)?;
        let mut loaded = Vec::new();
        let mut to_fetch = Vec::new();
        for txid in missing {
            match cached.get(&txid.to_string()) {
                Some(raw) => loaded.push((txid, raw.clone(), false)),
                None => to_fetch.push(txid),
            }
        }
        let fetched: Vec<(Txid, Vec<u8>, bool)> = stream::iter(to_fetch)
            .map(|txid| async move {
                let v = self.client.call("blockchain.transaction.get", json!([txid.to_string()])).await?;
                let raw = hex::decode(v.as_str().ok_or_else(|| anyhow!("unexpected reply for {txid}"))?)?;
                Ok::<_, anyhow::Error>((txid, raw, true))
            })
            .buffer_unordered(PARALLEL_REQUESTS)
            .try_collect()
            .await?;
        let mut new_raw = Vec::new();
        let mut txs = Vec::new();
        for (txid, raw, is_new) in loaded.into_iter().chain(fetched) {
            let tx: Transaction = consensus::deserialize(&raw).with_context(|| format!("decoding {txid}"))?;
            if tx.compute_txid() != txid {
                bail!("server returned the wrong transaction for {txid}");
            }
            if is_new {
                new_raw.push((txid.to_string(), raw));
            }
            txs.push((txid, Arc::new(tx)));
        }
        if !new_raw.is_empty() {
            self.store.put_raw_txs(&new_raw)?;
        }
        self.txs.lock().unwrap().extend(txs);
        Ok(())
    }

    pub fn add_wallet(self: &Arc<Self>, record: WalletRecord) -> Result<Arc<WalletRt>, String> {
        let w = self.make_runtime(record.clone())?;
        self.store.insert_wallet(&record).map_err(|e| e.to_string())?;
        self.wallets.write().unwrap().push(w.clone());
        info!("added wallet {} ({})", record.id, record.name);
        self.request_sync(w.clone());
        Ok(w)
    }

    pub fn update_wallet(self: &Arc<Self>, w: &Arc<WalletRt>, name: String, gap_limit: u32) -> anyhow::Result<()> {
        self.store.update_wallet(&w.id, &name, gap_limit)?;
        let grew = {
            let mut r = w.record.lock().unwrap();
            let grew = gap_limit > r.gap_limit;
            r.name = name;
            r.gap_limit = gap_limit;
            grew
        };
        if grew {
            self.request_sync(w.clone());
        }
        self.notify(Event::Wallet { id: w.id.clone() });
        Ok(())
    }

    pub fn remove_wallet(&self, id: &str) -> anyhow::Result<()> {
        self.store.delete_wallet(id)?;
        let removed = {
            let mut wallets = self.wallets.write().unwrap();
            let pos = wallets.iter().position(|w| w.id == id);
            pos.map(|p| wallets.remove(p))
        };
        if let Some(w) = removed {
            w.deleted.store(true, Ordering::Relaxed);
        }
        self.watchers.lock().unwrap().retain(|_, ids| {
            ids.remove(id);
            !ids.is_empty()
        });
        self.notify(Event::WalletRemoved { id: id.to_string() });
        Ok(())
    }

    /// Forget derived addresses and histories and scan again from scratch.
    pub async fn rescan(self: &Arc<Self>, w: &Arc<WalletRt>) {
        {
            let mut st = w.state.lock().await;
            *st = WalletState { by_chain: vec![Vec::new(); w.chains.len()], ..Default::default() };
        }
        self.request_sync(w.clone());
    }

    pub async fn tx_detail(&self, w: &WalletRt, txid: &Txid) -> Option<TxDetail> {
        let snapshot = w.snapshot()?;
        let row = snapshot.txs.iter().find(|r| r.txid == txid.to_string())?.clone();
        // Fetch parents not loaded during sync, to show input amounts and the fee.
        let missing: Vec<Txid> = {
            let txs = self.txs.lock().unwrap();
            let tx = txs.get(txid)?;
            if tx.is_coinbase() {
                Vec::new()
            } else {
                tx.input.iter().map(|i| i.previous_output.txid).filter(|p| !txs.contains_key(p)).collect()
            }
        };
        if !missing.is_empty() {
            match tokio::time::timeout(Duration::from_secs(30), self.ensure_txs(&missing)).await {
                Ok(Err(e)) => warn!("fetching parents of {txid}: {e:#}"),
                Err(_) => warn!("fetching parents of {txid} timed out"),
                Ok(Ok(())) => {}
            }
        }
        let txs = self.txs.lock().unwrap();
        let tx = txs.get(txid)?.clone();
        let mine = |script: &Script| {
            snapshot.mine.get(script).map(|(chain, index, _)| MineRef { chain: *chain, index: *index })
        };
        let inputs = tx
            .input
            .iter()
            .map(|i| {
                let prev = (!tx.is_coinbase())
                    .then(|| {
                        txs.get(&i.previous_output.txid).and_then(|p| p.output.get(i.previous_output.vout as usize))
                    })
                    .flatten();
                InputDetail {
                    prev_txid: i.previous_output.txid.to_string(),
                    vout: i.previous_output.vout,
                    coinbase: tx.is_coinbase(),
                    value: prev.map(|o| o.value.to_sat()),
                    address: prev.map(|o| describe_script(&o.script_pubkey, self.network)),
                    mine: prev.and_then(|o| mine(&o.script_pubkey)),
                }
            })
            .collect();
        let outputs = tx
            .output
            .iter()
            .enumerate()
            .map(|(n, o)| OutputDetail {
                n: n as u32,
                value: o.value.to_sat(),
                address: describe_script(&o.script_pubkey, self.network),
                mine: mine(&o.script_pubkey),
                spent_by_wallet: !snapshot.utxos.iter().any(|u| u.txid == row.txid && u.vout == n as u32)
                    && mine(&o.script_pubkey).is_some(),
            })
            .collect();
        Some(TxDetail {
            txid: row.txid.clone(),
            height: row.height,
            time: row.time,
            net: row.net,
            fee: row.fee.or_else(|| {
                let inputs: Option<u64> = (!tx.is_coinbase())
                    .then(|| {
                        tx.input.iter().try_fold(0u64, |sum, i| {
                            let prev = txs.get(&i.previous_output.txid)?;
                            Some(sum + prev.output.get(i.previous_output.vout as usize)?.value.to_sat())
                        })
                    })
                    .flatten();
                inputs?.checked_sub(tx.output.iter().map(|o| o.value.to_sat()).sum())
            }),
            vsize: row.vsize,
            weight: tx.weight().to_wu(),
            size: consensus::serialize(&*tx).len() as u64,
            version: tx.version.0,
            locktime: tx.lock_time.to_consensus_u32(),
            rbf: tx.is_explicitly_rbf(),
            inputs,
            outputs,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MineRef {
    pub chain: ChainKind,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputDetail {
    pub prev_txid: String,
    pub vout: u32,
    pub coinbase: bool,
    pub value: Option<u64>,
    pub address: Option<String>,
    pub mine: Option<MineRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputDetail {
    pub n: u32,
    pub value: u64,
    pub address: String,
    pub mine: Option<MineRef>,
    pub spent_by_wallet: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxDetail {
    pub txid: String,
    pub height: i64,
    pub time: Option<u64>,
    pub net: i64,
    pub fee: Option<u64>,
    pub vsize: u64,
    pub weight: u64,
    pub size: u64,
    pub version: i32,
    pub locktime: u32,
    pub rbf: bool,
    pub inputs: Vec<InputDetail>,
    pub outputs: Vec<OutputDetail>,
}

fn describe_script(script: &Script, network: Network) -> String {
    if script.is_op_return() {
        return "OP_RETURN".into();
    }
    address_of(&script.to_owned(), network).unwrap_or_else(|| format!("script {}", script.to_hex_string()))
}

fn parse_history(v: &Value) -> anyhow::Result<Vec<HistItem>> {
    let items = v.as_array().ok_or_else(|| anyhow!("history is not a list"))?;
    items
        .iter()
        .map(|item| {
            let txid = item.get("tx_hash").and_then(Value::as_str).ok_or_else(|| anyhow!("missing tx_hash"))?;
            let height = item.get("height").and_then(Value::as_i64).ok_or_else(|| anyhow!("missing height"))?;
            Ok(HistItem { txid: txid.parse()?, height })
        })
        .collect()
}

/// Sort key that puts mempool transactions after all confirmed ones.
fn chrono_height(h: i64) -> i64 {
    if h > 0 { h } else { i64::MAX }
}

/// Compute balances, history, UTXOs and address stats. Pure; unit-tested.
pub fn build_snapshot(
    entries: &[AddrEntry],
    histories: &HashMap<String, History>,
    txs: &HashMap<Txid, Arc<Transaction>>,
    times: &HashMap<i64, u32>,
    first_seen: &HashMap<Txid, u64>,
) -> Snapshot {
    let by_script: HashMap<&Script, usize> =
        entries.iter().enumerate().map(|(i, e)| (e.script.as_script(), i)).collect();

    // Unique transactions in first-seen order, with heights.
    let mut order: Vec<(Txid, i64)> = Vec::new();
    let mut seen = HashSet::new();
    for e in entries {
        for item in histories.get(&e.script_hash).map(|h| h.1.as_slice()).unwrap_or_default() {
            if seen.insert(item.txid) {
                order.push((item.txid, item.height));
            }
        }
    }
    order.sort_by_key(|(_, h)| chrono_height(*h)); // stable
    let order = topo_within_heights(order, txs);

    let mut received = vec![0u64; entries.len()];
    let mut sent = vec![0u64; entries.len()];
    let mut unspent: HashMap<OutPoint, (u64, usize, i64)> = HashMap::new();
    let mut spent: HashSet<OutPoint> = HashSet::new();
    let mut rows = Vec::new();
    let mut balance = Balance::default();
    let mut running = 0i64;

    for (txid, height) in order {
        let Some(tx) = txs.get(&txid) else { continue };
        let mut tx_received = 0u64;
        let mut tx_sent = 0u64;
        let mut inputs_total = 0u64;
        let mut inputs_known = !tx.is_coinbase();
        for (n, out) in tx.output.iter().enumerate() {
            if let Some(&i) = by_script.get(out.script_pubkey.as_script()) {
                let v = out.value.to_sat();
                tx_received += v;
                received[i] += v;
                unspent.insert(OutPoint { txid, vout: n as u32 }, (v, i, height));
            }
        }
        if !tx.is_coinbase() {
            for input in &tx.input {
                spent.insert(input.previous_output);
                let prev_out = txs
                    .get(&input.previous_output.txid)
                    .and_then(|p| p.output.get(input.previous_output.vout as usize));
                match prev_out {
                    Some(out) => {
                        let v = out.value.to_sat();
                        inputs_total += v;
                        if let Some(&i) = by_script.get(out.script_pubkey.as_script()) {
                            tx_sent += v;
                            sent[i] += v;
                        }
                    }
                    None => inputs_known = false,
                }
            }
        }
        let outputs_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = inputs_known.then(|| inputs_total.checked_sub(outputs_total)).flatten();
        let net = tx_received as i64 - tx_sent as i64;
        running += net;
        if height > 0 {
            balance.confirmed += net;
        } else {
            balance.unconfirmed += net;
        }
        let time = if height > 0 { times.get(&height).map(|t| *t as u64) } else { first_seen.get(&txid).copied() };
        rows.push(TxRow {
            txid: txid.to_string(),
            height,
            time,
            net,
            fee,
            vsize: tx.vsize() as u64,
            balance_after: running,
        });
    }
    balance.total = balance.confirmed + balance.unconfirmed;
    rows.reverse();

    let mut utxos: Vec<UtxoRow> = unspent
        .into_iter()
        .filter(|(op, _)| !spent.contains(op))
        .map(|(op, (value, i, height))| UtxoRow {
            txid: op.txid.to_string(),
            vout: op.vout,
            value,
            address: entries[i].address.clone(),
            chain: entries[i].chain,
            index: entries[i].index,
            height,
        })
        .collect();
    utxos.sort_by(|a, b| chrono_height(b.height).cmp(&chrono_height(a.height)).then(b.value.cmp(&a.value)));

    let addresses: Vec<AddrRow> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| AddrRow {
            address: e.address.clone(),
            chain: e.chain,
            index: e.index,
            tx_count: histories.get(&e.script_hash).map_or(0, |h| h.1.len()),
            received: received[i],
            balance: received[i] as i64 - sent[i] as i64,
        })
        .collect();

    let receive: Vec<&AddrRow> = addresses.iter().filter(|a| a.chain == ChainKind::Receive).collect();
    let last_used = receive.iter().filter(|a| a.tx_count > 0).map(|a| a.index).max();
    let next_receive = receive
        .iter()
        .filter(|a| last_used.is_none_or(|u| a.index > u))
        .min_by_key(|a| a.index)
        .map(|a| AddrRef { address: a.address.clone(), index: a.index });

    let mine = entries.iter().map(|e| (e.script.clone(), (e.chain, e.index, e.address.clone()))).collect();
    Snapshot { balance, txs: rows, utxos, addresses, next_receive, mine }
}

/// Within each group of equal height, place a transaction after any
/// transaction in the same group whose outputs it spends.
fn topo_within_heights(order: Vec<(Txid, i64)>, txs: &HashMap<Txid, Arc<Transaction>>) -> Vec<(Txid, i64)> {
    let mut out = Vec::with_capacity(order.len());
    let mut start = 0;
    while start < order.len() {
        let h = chrono_height(order[start].1);
        let end = start + order[start..].iter().take_while(|(_, x)| chrono_height(*x) == h).count();
        let group = &order[start..end];
        if group.len() == 1 {
            out.push(group[0]);
        } else {
            let in_group: HashSet<Txid> = group.iter().map(|(t, _)| *t).collect();
            let mut placed: HashSet<Txid> = HashSet::new();
            let mut remaining: Vec<(Txid, i64)> = group.to_vec();
            while !remaining.is_empty() {
                let before = remaining.len();
                remaining.retain(|(txid, height)| {
                    let ready = txs.get(txid).is_none_or(|tx| {
                        tx.input.iter().all(|i| {
                            let p = i.previous_output.txid;
                            p == *txid || !in_group.contains(&p) || placed.contains(&p)
                        })
                    });
                    if ready {
                        placed.insert(*txid);
                        out.push((*txid, *height));
                    }
                    !ready
                });
                if remaining.len() == before {
                    // Cycle (can't happen in valid chains); keep original order.
                    out.append(&mut remaining);
                }
            }
        }
        start = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::absolute::LockTime;
    use miniscript::bitcoin::transaction::Version;
    use miniscript::bitcoin::{Amount, Sequence, TxIn, TxOut, Witness};

    fn script(n: u8) -> ScriptBuf {
        let mut b = vec![0x00, 0x14];
        b.extend([n; 20]);
        ScriptBuf::from(b)
    }

    fn entry(n: u8, chain: ChainKind, index: u32) -> AddrEntry {
        let s = script(n);
        AddrEntry {
            script_hash: script_hash(&s),
            address: address_of(&s, Network::Bitcoin).unwrap(),
            script: s,
            chain,
            index,
        }
    }

    fn tx(inputs: &[(Txid, u32)], outputs: &[(u8, u64)]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(txid, vout)| TxIn {
                    previous_output: OutPoint { txid: *txid, vout: *vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(s, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: script(*s) })
                .collect(),
        }
    }

    #[test]
    fn balances_fees_and_utxos() {
        // Funding from outside (script 9 is not ours), then a spend with change,
        // then an unconfirmed incoming payment.
        let outside = tx(&[(Txid::all_zeros(), 7)], &[(9, 100_000)]);
        let fund = tx(&[(outside.compute_txid(), 0)], &[(1, 60_000), (9, 39_000)]); // fee 1000
        let spend = tx(&[(fund.compute_txid(), 0)], &[(9, 20_000), (2, 39_500)]); // fee 500, change to 2
        let incoming = tx(&[(outside.compute_txid(), 0)], &[(3, 5_000)]); // conflicting-but-whatever input, fee unknown? no: known

        let entries = vec![
            entry(1, ChainKind::Receive, 0),
            entry(3, ChainKind::Receive, 1),
            entry(4, ChainKind::Receive, 2),
            entry(2, ChainKind::Change, 0),
        ];
        let mut histories = HashMap::new();
        let h = |items: &[(&Transaction, i64)]| -> History {
            (Some("x".into()), items.iter().map(|(t, h)| HistItem { txid: t.compute_txid(), height: *h }).collect())
        };
        histories.insert(entries[0].script_hash.clone(), h(&[(&fund, 100), (&spend, 101)]));
        histories.insert(entries[1].script_hash.clone(), h(&[(&incoming, 0)]));
        histories.insert(entries[2].script_hash.clone(), (None, vec![]));
        histories.insert(entries[3].script_hash.clone(), h(&[(&spend, 101)]));

        let mut txs = HashMap::new();
        for t in [&outside, &fund, &spend, &incoming] {
            txs.insert(t.compute_txid(), Arc::new((*t).clone()));
        }
        let times = HashMap::from([(100, 1_700_000_000u32), (101, 1_700_000_600u32)]);
        let s = build_snapshot(&entries, &histories, &txs, &times, &HashMap::new());

        assert_eq!(s.balance.confirmed, 39_500);
        assert_eq!(s.balance.unconfirmed, 5_000);
        assert_eq!(s.balance.total, 44_500);
        assert_eq!(s.utxos.iter().map(|u| u.value as i64).sum::<i64>(), s.balance.total);
        assert_eq!(s.utxos.len(), 2);

        // newest first
        let ids: Vec<&str> = s.txs.iter().map(|r| r.txid.as_str()).collect();
        assert_eq!(
            ids,
            [incoming.compute_txid().to_string(), spend.compute_txid().to_string(), fund.compute_txid().to_string()]
        );
        assert_eq!(s.txs[1].net, -20_500);
        assert_eq!(s.txs[1].fee, Some(500));
        assert_eq!(s.txs[2].fee, Some(1_000));
        assert_eq!(s.txs[2].time, Some(1_700_000_000));
        assert_eq!(s.txs[0].balance_after, 44_500);

        // receive index 1 is used, so the next fresh one is index 2
        assert_eq!(s.next_receive.as_ref().unwrap().index, 2);
        let a0 = s.addresses.iter().find(|a| a.chain == ChainKind::Receive && a.index == 0).unwrap();
        assert_eq!((a0.tx_count, a0.received, a0.balance), (2, 60_000, 0));
    }

    #[test]
    fn same_block_parent_ordered_first() {
        let a = tx(&[(Txid::all_zeros(), 1)], &[(1, 1_000)]);
        let b = tx(&[(a.compute_txid(), 0)], &[(2, 900)]);
        let mut txs = HashMap::new();
        txs.insert(a.compute_txid(), Arc::new(a.clone()));
        txs.insert(b.compute_txid(), Arc::new(b.clone()));
        let order = vec![(b.compute_txid(), 5), (a.compute_txid(), 5)];
        let sorted = topo_within_heights(order, &txs);
        assert_eq!(sorted[0].0, a.compute_txid());
    }

    #[test]
    fn script_hash_matches_electrum() {
        // Electrum protocol docs example: P2PKH for 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        let s = ScriptBuf::from(hex::decode("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac").unwrap());
        assert_eq!(script_hash(&s), "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161");
    }
}
