//! SQLite persistence: wallet definitions, labels, and a raw transaction
//! cache (transactions are immutable, so cached entries never go stale).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::wallet::WalletSpec;

#[derive(Debug, Clone, Serialize)]
pub struct WalletRecord {
    pub id: String,
    pub name: String,
    pub spec: WalletSpec,
    pub gap_limit: u32,
    pub created_at: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS wallets (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 spec TEXT NOT NULL,
                 gap_limit INTEGER NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS txs (txid TEXT PRIMARY KEY, raw BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS labels (
                 wallet_id TEXT NOT NULL,
                 txid TEXT NOT NULL,
                 label TEXT NOT NULL,
                 PRIMARY KEY (wallet_id, txid)
             );
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn wallets(&self) -> anyhow::Result<Vec<WalletRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, name, spec, gap_limit, created_at FROM wallets ORDER BY created_at, id")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get::<_, String>(2)?, r.get(3)?, r.get(4)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, spec, gap_limit, created_at) = row?;
            let spec = serde_json::from_str(&spec).with_context(|| format!("wallet {id}: bad spec"))?;
            out.push(WalletRecord { id, name, spec, gap_limit, created_at });
        }
        Ok(out)
    }

    pub fn insert_wallet(&self, w: &WalletRecord) -> anyhow::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO wallets (id, name, spec, gap_limit, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![w.id, w.name, serde_json::to_string(&w.spec)?, w.gap_limit, w.created_at],
        )?;
        Ok(())
    }

    pub fn update_wallet(&self, id: &str, name: &str, gap_limit: u32) -> anyhow::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("UPDATE wallets SET name = ?2, gap_limit = ?3 WHERE id = ?1", params![id, name, gap_limit])?;
        Ok(())
    }

    pub fn delete_wallet(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM wallets WHERE id = ?1", params![id])?;
        conn.execute("DELETE FROM labels WHERE wallet_id = ?1", params![id])?;
        Ok(())
    }

    pub fn raw_txs(&self, txids: &[String]) -> anyhow::Result<HashMap<String, Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT raw FROM txs WHERE txid = ?1")?;
        let mut out = HashMap::new();
        for txid in txids {
            if let Some(raw) = stmt.query_row(params![txid], |r| r.get::<_, Vec<u8>>(0)).optional()? {
                out.insert(txid.clone(), raw);
            }
        }
        Ok(out)
    }

    pub fn put_raw_txs(&self, txs: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let db = conn.transaction()?;
        {
            let mut stmt = db.prepare_cached("INSERT OR IGNORE INTO txs (txid, raw) VALUES (?1, ?2)")?;
            for (txid, raw) in txs {
                stmt.execute(params![txid, raw])?;
            }
        }
        db.commit()?;
        Ok(())
    }

    pub fn labels(&self, wallet_id: &str) -> anyhow::Result<HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT txid, label FROM labels WHERE wallet_id = ?1")?;
        let rows = stmt.query_map(params![wallet_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn set_label(&self, wallet_id: &str, txid: &str, label: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        if label.is_empty() {
            conn.execute("DELETE FROM labels WHERE wallet_id = ?1 AND txid = ?2", params![wallet_id, txid])?;
        } else {
            conn.execute(
                "INSERT INTO labels (wallet_id, txid, label) VALUES (?1, ?2, ?3)
                 ON CONFLICT (wallet_id, txid) DO UPDATE SET label = excluded.label",
                params![wallet_id, txid, label],
            )?;
        }
        Ok(())
    }

    pub fn meta(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}
